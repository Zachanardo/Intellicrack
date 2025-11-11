"""Process common utilities for Intellicrack.

This file is part of Intellicrack.
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

Common process handling utilities.

This module consolidates process creation and management patterns.
"""

import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def run_subprocess_safely(cmd: list[str], timeout: int = 30, capture_output: bool = True) -> subprocess.CompletedProcess:
    """Run a subprocess with common safety patterns.

    Args:
        cmd: Command and arguments list
        timeout: Timeout in seconds
        capture_output: Whether to capture stdout/stderr

    Returns:
        CompletedProcess result

    """
    try:
        return subprocess.run(  # nosec S603 - Legitimate subprocess usage for security research and binary analysis
            cmd,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %d seconds: %s", timeout, cmd[0])
        raise
    except FileNotFoundError:
        logger.error("Command not found: %s", cmd[0])
        raise


def create_popen_safely(cmd: list[str], **kwargs) -> subprocess.Popen:
    """Create a Popen process with common patterns.

    Args:
        cmd: Command and arguments list
        **kwargs: Additional Popen arguments

    Returns:
        Popen process object

    """
    defaults = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    defaults.update(kwargs)

    return subprocess.Popen(cmd, **defaults)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis


def create_suspended_process_with_context(create_func, get_context_func, target_exe: str, logger_instance=None) -> dict[str, Any]:
    """Provide pattern for creating suspended process and getting thread context.

    Args:
        create_func: Function to create suspended process
        get_context_func: Function to get thread context
        target_exe: Target executable path
        logger_instance: Optional logger instance

    Returns:
        dict: Contains process_info and context, or error info

    """
    if logger_instance is None:
        logger_instance = logger

    try:
        # Create process in suspended state
        process_info = create_func(target_exe)
        if not process_info:
            error_msg = "Failed to create suspended process"
            logger_instance.error(error_msg)
            return {"success": False, "error": error_msg}

        # Get thread context
        context = get_context_func(process_info["thread_handle"])
        if not context:
            error_msg = "Failed to get thread context"
            logger_instance.error(error_msg)
            return {"success": False, "error": error_msg, "process_info": process_info}

        return {
            "success": True,
            "process_info": process_info,
            "context": context,
        }

    except Exception as e:
        error_msg = f"Error in process creation: {e!s}"
        logger_instance.error(error_msg)
        return {"success": False, "error": error_msg}
