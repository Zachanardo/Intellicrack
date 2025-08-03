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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Shared subprocess utilities for Intellicrack.

This module provides common subprocess execution patterns.
"""

import logging
import subprocess

logger = logging.getLogger(__name__)


def run_subprocess(
    cmd: str | list[str],
    timeout: int | None = None,
    capture_output: bool = True,
    text: bool = True,
    cwd: str | None = None,
    env: dict | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess command with standard error handling.

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
            env=env,
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


def run_subprocess_check(
    cmd: str | list[str],
    timeout: int = 10,
    capture_output: bool = True,
    text: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess:
    """Run subprocess with standard settings used in docker_container and qemu_emulator.

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
            check=check,
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


def create_popen_with_encoding(
    cmd: list[str], encoding: str = "utf-8", timeout: int | None = None
) -> tuple[int, str, str]:
    """Create Popen process with encoding and error handling.

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
            errors="replace",
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
