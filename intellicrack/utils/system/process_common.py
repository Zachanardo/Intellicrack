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
from collections.abc import Callable
from typing import Any


logger = logging.getLogger(__name__)


def run_subprocess_safely(cmd: list[str], timeout: int = 30, capture_output: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with common safety patterns.

    Args:
        cmd: Command and arguments list
        timeout: Timeout in seconds
        capture_output: Whether to capture stdout/stderr

    Returns:
        Completed subprocess result with returncode, stdout, and stderr

    Raises:
        FileNotFoundError: If command executable not found
        subprocess.TimeoutExpired: If command exceeds timeout duration

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
        logger.exception("Command timed out after %d seconds: %s", timeout, cmd[0])
        raise
    except FileNotFoundError:
        logger.exception("Command not found: %s", cmd[0])
        raise


def create_popen_safely(cmd: list[str], **kwargs: Any) -> subprocess.Popen[str]:
    """Create a Popen process with common patterns.

    Args:
        cmd: Command and arguments list
        **kwargs: Additional Popen arguments

    Returns:
        Running process with stdout and stderr piped to caller

    Raises:
        FileNotFoundError: If command executable not found
        OSError: If process creation fails

    """
    defaults: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    defaults.update(kwargs)
    return subprocess.Popen(cmd, **defaults)  # nosec S603 - Legitimate subprocess usage for security research and binary analysis


def create_suspended_process_with_context(
    create_func: Callable[[str], dict[str, Any] | None],
    get_context_func: Callable[[Any], Any],
    target_exe: str,
    logger_instance: logging.Logger | None = None,
) -> dict[str, Any]:
    """Provide pattern for creating suspended process and getting thread context.

    Args:
        create_func: Function to create suspended process
        get_context_func: Function to get thread context
        target_exe: Target executable path
        logger_instance: Optional logger instance

    Returns:
        Dictionary containing success status, process_info, context on success, or
        error information on failure

    Raises:
        Exception: If process creation or context retrieval fails

    """
    if logger_instance is None:
        logger_instance = logger

    try:
        # Create process in suspended state
        process_info = create_func(target_exe)
        if not process_info:
            error_msg = "Failed to create suspended process"
            logger_instance.exception(error_msg)
            return {"success": False, "error": error_msg}

        # Get thread context
        context = get_context_func(process_info["thread_handle"])
        if not context:
            error_msg = "Failed to get thread context"
            logger_instance.exception(error_msg)
            return {"success": False, "error": error_msg, "process_info": process_info}

        return {
            "success": True,
            "process_info": process_info,
            "context": context,
        }

    except Exception as e:
        error_msg = f"Error in process creation: {e!s}"
        logger_instance.exception(error_msg)
        return {"success": False, "error": error_msg}
