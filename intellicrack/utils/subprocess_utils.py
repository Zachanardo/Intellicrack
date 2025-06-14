"""
Shared subprocess utilities for Intellicrack.

This module provides common subprocess execution patterns.
"""

import logging
import subprocess
from typing import Tuple, Optional, List, Union


logger = logging.getLogger(__name__)


def run_subprocess(cmd: Union[str, List[str]], 
                  timeout: Optional[int] = None,
                  capture_output: bool = True,
                  text: bool = True,
                  cwd: Optional[str] = None,
                  env: Optional[dict] = None) -> Tuple[int, str, str]:
    """
    Run a subprocess command with standard error handling.
    
    Args:
        cmd: Command to run (string or list)
        timeout: Timeout in seconds
        capture_output: Whether to capture stdout/stderr
        text: Whether to return text instead of bytes
        cwd: Working directory
        env: Environment variables
        
    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    try:
        # Convert string command to list if needed
        if isinstance(cmd, str):
            cmd = cmd.split()
            
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=text,
            cwd=cwd,
            env=env
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            logger.warning("Process timed out after %s seconds", timeout)
            
        return process.returncode, stdout or "", stderr or ""
        
    except Exception as e:
        logger.error("Error running subprocess: %s", e)
        return -1, "", str(e)


def run_subprocess_check(cmd: Union[str, List[str]], 
                        timeout: int = 10,
                        capture_output: bool = True,
                        text: bool = True,
                        check: bool = False) -> subprocess.CompletedProcess:
    """
    Run subprocess with standard settings used in docker_container and qemu_emulator.
    
    This is the common pattern extracted from duplicate code.
    
    Args:
        cmd: Command to run
        timeout: Timeout in seconds (default 10)
        capture_output: Whether to capture output (default True)
        text: Whether to return text (default True) 
        check: Whether to check return code (default False)
        
    Returns:
        CompletedProcess object
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            check=check
        )
        return result
        
    except subprocess.TimeoutExpired as e:
        logger.warning("Command timed out after %s seconds: %s", timeout, cmd)
        raise
    except subprocess.CalledProcessError as e:
        logger.error("Command failed with return code %s: %s", e.returncode, cmd)
        raise
    except Exception as e:
        logger.error("Error running command %s: %s", cmd, e)
        raise