"""
Common process handling utilities.

This module consolidates process creation and management patterns.
"""

import logging
import subprocess
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

def run_subprocess_safely(cmd: List[str], timeout: int = 30, capture_output: bool = True) -> subprocess.CompletedProcess:
    """
    Run a subprocess with common safety patterns.

    Args:
        cmd: Command and arguments list
        timeout: Timeout in seconds
        capture_output: Whether to capture stdout/stderr

    Returns:
        CompletedProcess result
    """
    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=True,
            timeout=timeout,
            check=False
        )
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %d seconds: %s", timeout, cmd[0])
        raise
    except FileNotFoundError:
        logger.error("Command not found: %s", cmd[0])
        raise

def create_popen_safely(cmd: List[str], **kwargs) -> subprocess.Popen:
    """
    Create a Popen process with common patterns.

    Args:
        cmd: Command and arguments list
        **kwargs: Additional Popen arguments

    Returns:
        Popen process object
    """
    defaults = {
        'stdout': subprocess.PIPE,
        'stderr': subprocess.PIPE,
        'text': True
    }
    defaults.update(kwargs)

    return subprocess.Popen(cmd, **defaults)


def create_suspended_process_with_context(create_func, get_context_func, target_exe: str,
                                        logger_instance=None) -> Dict[str, Any]:
    """
    Common pattern for creating suspended process and getting thread context.

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
        context = get_context_func(process_info['thread_handle'])
        if not context:
            error_msg = "Failed to get thread context"
            logger_instance.error(error_msg)
            return {"success": False, "error": error_msg, "process_info": process_info}

        return {
            "success": True,
            "process_info": process_info,
            "context": context
        }

    except Exception as e:
        error_msg = f"Error in process creation: {str(e)}"
        logger_instance.error(error_msg)
        return {"success": False, "error": error_msg}
