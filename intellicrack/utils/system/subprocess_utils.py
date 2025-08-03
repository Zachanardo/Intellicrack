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

"""
Shared subprocess utilities for Intellicrack.

This module provides common subprocess execution patterns.
"""

import asyncio
import logging
import subprocess
from typing import List, Optional, Tuple, Union

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

    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %s seconds: %s", timeout, cmd)
        raise
    except subprocess.CalledProcessError as e:
        logger.error("Command failed with return code %s: %s", e.returncode, cmd)
        raise
    except Exception as e:
        logger.error("Error running command %s: %s", cmd, e)
        raise


def create_popen_with_encoding(cmd: List[str], encoding: str = "utf-8",
                              timeout: Optional[int] = None) -> Tuple[int, str, str]:
    """
    Create Popen process with encoding and error handling.

    Common pattern for process creation with output capture and encoding.

    Args:
        cmd: Command list to execute
        encoding: Text encoding for output (default: utf-8)
        timeout: Optional timeout in seconds

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding=encoding,
            errors='replace'
        )

        if timeout:
            stdout, stderr = process.communicate(timeout=timeout)
        else:
            stdout, stderr = process.communicate()

        return process.returncode, stdout or "", stderr or ""

    except subprocess.TimeoutExpired:
        logger.warning("Process timed out after %s seconds", timeout)
        process.kill()
        stdout, stderr = process.communicate()
        return -1, stdout or "", stderr or ""
    except Exception as e:
        logger.error("Error creating process: %s", e)
        return -1, "", str(e)


# Async subprocess utilities for non-blocking execution

async def async_run_subprocess(cmd: Union[str, List[str]],
                              timeout: Optional[int] = None,
                              capture_output: bool = True,
                              text: bool = True,
                              cwd: Optional[str] = None,
                              env: Optional[dict] = None) -> Tuple[int, str, str]:
    """
    Async version of run_subprocess for non-blocking execution.
    
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
            # Use shell=True for string commands
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE if capture_output else None,
                stderr=asyncio.subprocess.PIPE if capture_output else None,
                cwd=cwd,
                env=env
            )
        else:
            # Use exec for list commands
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE if capture_output else None,
                stderr=asyncio.subprocess.PIPE if capture_output else None,
                cwd=cwd,
                env=env
            )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), 
                timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning("Process timed out after %s seconds", timeout)
            return -1, "", "Process timed out"
        
        # Decode output if text mode requested
        if text and stdout is not None:
            stdout = stdout.decode('utf-8', errors='replace')
        if text and stderr is not None:
            stderr = stderr.decode('utf-8', errors='replace')
            
        return proc.returncode, stdout or "", stderr or ""
        
    except Exception as e:
        logger.error("Error running async subprocess: %s", e)
        return -1, "", str(e)


async def async_run_subprocess_check(cmd: Union[str, List[str]],
                                   timeout: int = 10,
                                   capture_output: bool = True,
                                   text: bool = True,
                                   check: bool = False) -> dict:
    """
    Async version of run_subprocess_check.
    
    Args:
        cmd: Command to run
        timeout: Timeout in seconds (default 10)
        capture_output: Whether to capture output (default True)
        text: Whether to return text (default True)
        check: Whether to check return code (default False)
        
    Returns:
        Dict with keys: returncode, stdout, stderr
    """
    returncode, stdout, stderr = await async_run_subprocess(
        cmd, 
        timeout=timeout, 
        capture_output=capture_output, 
        text=text
    )
    
    result = {
        'returncode': returncode,
        'stdout': stdout,
        'stderr': stderr
    }
    
    if check and returncode != 0:
        logger.error("Command failed with return code %s: %s", returncode, cmd)
        raise subprocess.CalledProcessError(returncode, cmd, stdout, stderr)
        
    return result


async def async_create_popen_with_encoding(cmd: List[str], encoding: str = "utf-8",
                                         timeout: Optional[int] = None) -> Tuple[int, str, str]:
    """
    Async version of create_popen_with_encoding.
    
    Args:
        cmd: Command list to execute
        encoding: Text encoding for output (default: utf-8)
        timeout: Optional timeout in seconds
        
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        if timeout:
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning("Process timed out after %s seconds", timeout)
                proc.kill()
                await proc.wait()
                return -1, "", "Process timed out"
        else:
            stdout, stderr = await proc.communicate()
            
        # Decode with specified encoding
        stdout_str = stdout.decode(encoding, errors='replace') if stdout else ""
        stderr_str = stderr.decode(encoding, errors='replace') if stderr else ""
        
        return proc.returncode, stdout_str, stderr_str
        
    except Exception as e:
        logger.error("Error creating async process: %s", e)
        return -1, "", str(e)
