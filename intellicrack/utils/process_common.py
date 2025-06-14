"""
Common process handling utilities.

This module consolidates process creation and management patterns.
"""

import logging
import subprocess
from typing import List

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
