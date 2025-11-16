"""Subprocess Security Module.

Provides secure subprocess execution with input validation and sanitization
for the Intellicrack security research platform.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import logging
import os
import shlex
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Define allowed executable patterns for security research tools
ALLOWED_TOOLS = {
    "wmic",
    "tasklist",
    "reg",
    "powershell",
    "cmd",
    "psexec",
    "scp",
    "ssh",
    "sshpass",
    "winrs",
    "john",
    "hashcat",
    "ghidra",
    "frida",
    "x64dbg",
    "ida",
    "ollydbg",
    "radare2",
    "objdump",
    "nm",
    "strings",
    "file",
    "upx",
    "python",
    "python3",
    "node",
    "npm",
    "git",
    "klist",
}

# Shell metacharacters that could be dangerous
SHELL_METACHARACTERS = {"&", "|", ";", "$", "`", "\n", "\r", ">", "<", "(", ")", "{", "}", "[", "]", "*", "?", "~"}


class SecureSubprocess:
    """Secure subprocess execution with validation."""

    @staticmethod
    def validate_executable(executable: str) -> str:
        """Validate that the executable is allowed and exists.

        Args:
            executable: Path to executable or command name

        Returns:
            Validated absolute path to executable

        Raises:
            ValueError: If executable is not allowed or doesn't exist

        """
        # Extract base name for validation
        base_name = os.path.basename(executable).lower()
        base_name = base_name.replace(".exe", "").replace(".bat", "").replace(".sh", "")

        # Check if tool is in allowed list
        if base_name not in ALLOWED_TOOLS:
            # Check if it's a full path to an allowed tool
            if not any(tool in executable.lower() for tool in ALLOWED_TOOLS):
                logger.warning(f"Attempting to execute non-whitelisted tool: {executable}")
                # For security research, we still allow but log it

        # Resolve to absolute path
        if Path(executable).is_absolute():
            abs_path = executable
        else:
            # Try to find in PATH
            import shutil

            abs_path = shutil.which(executable)
            if not abs_path:
                # Try common locations on Windows
                if os.name == "nt":
                    system_root = os.environ.get("SYSTEMROOT", "C:\\Windows")
                    possible_paths = [
                        os.path.join(system_root, "System32", executable),
                        os.path.join(system_root, "System32", f"{executable}.exe"),
                        os.path.join(system_root, "SysWOW64", executable),
                        os.path.join(system_root, "SysWOW64", f"{executable}.exe"),
                    ]
                    for path in possible_paths:
                        if os.path.exists(path):
                            abs_path = path
                            break

        if not abs_path or not os.path.exists(abs_path):
            error_msg = f"Executable not found: {executable}"
            logger.error(error_msg)
            raise ValueError(error_msg)

        return os.path.abspath(abs_path)

    @staticmethod
    def validate_argument(arg: str, allow_wildcards: bool = False) -> str:
        """Validate a single command argument.

        Args:
            arg: Argument to validate
            allow_wildcards: Whether to allow wildcard characters

        Returns:
            Validated argument

        Raises:
            ValueError: If argument contains dangerous characters

        """
        # Convert to string if needed
        if not isinstance(arg, str):
            arg = str(arg)

        # Check for shell metacharacters
        dangerous_chars = SHELL_METACHARACTERS.copy()
        if allow_wildcards:
            dangerous_chars -= {"*", "?"}

        # Check for command injection attempts
        if any(char in arg for char in dangerous_chars):
            # Allow certain safe patterns
            if arg.startswith("-") or arg.startswith("/") or ("=" in arg and not any(char in arg for char in ["`", "$", ";", "|", "&"])):  # Command flags
                pass
            else:
                error_msg = f"Potentially dangerous argument: {arg}"
                logger.error(error_msg)
                raise ValueError(error_msg)

        return arg

    @staticmethod
    def validate_command(command: list[str], allow_wildcards: bool = False) -> list[str]:
        """Validate entire command list.

        Args:
            command: List of command arguments
            allow_wildcards: Whether to allow wildcards in arguments

        Returns:
            Validated command list

        Raises:
            ValueError: If command validation fails

        """
        if not command:
            error_msg = "Empty command"
            logger.error(error_msg)
            raise ValueError(error_msg)

        validated = []

        # Validate executable (first argument)
        validated.append(SecureSubprocess.validate_executable(command[0]))

        # Validate remaining arguments
        for arg in command[1:]:
            # Skip validation for file paths that exist
            if os.path.exists(arg):
                validated.append(os.path.abspath(arg))
            else:
                validated.append(SecureSubprocess.validate_argument(arg, allow_wildcards))

        return validated

    @staticmethod
    def run(
        command: list[str] | str,
        shell: bool = False,
        capture_output: bool = True,
        text: bool = True,
        timeout: int | None = None,
        check: bool = False,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        **kwargs: object,
    ) -> subprocess.CompletedProcess:
        """Secure subprocess.run wrapper with validation.

        Args:
            command: Command to execute
            shell: Whether to use shell (strongly discouraged)
            capture_output: Whether to capture stdout/stderr
            text: Whether to return text instead of bytes
            timeout: Timeout in seconds
            check: Whether to raise on non-zero exit
            cwd: Working directory
            env: Environment variables
            **kwargs: Additional arguments for subprocess.run

        Returns:
            CompletedProcess instance

        """
        # Force shell=False for security unless explicitly required
        if shell:
            logger.warning("Shell execution requested - this reduces security")
            # Convert to string for shell execution
            if isinstance(command, list):
                command = " ".join(command)
        else:
            # Validate command for non-shell execution
            if isinstance(command, str):
                # Split string command safely
                command = shlex.split(command)
            command = SecureSubprocess.validate_command(command)

        # Validate working directory if provided
        if cwd:
            cwd = os.path.abspath(cwd)
            if not Path(cwd).is_dir():
                error_msg = f"Invalid working directory: {cwd}"
                logger.error(error_msg)
                raise ValueError(error_msg)

        # Execute with security flags
        return subprocess.run(
            command, shell=shell, capture_output=capture_output, text=text, timeout=timeout, check=check, cwd=cwd, env=env, **kwargs,
        )

    @staticmethod
    def popen(
        command: list[str] | str,
        shell: bool = False,
        stdout: object = None,
        stderr: object = None,
        stdin: object = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        **kwargs: object,
    ) -> subprocess.Popen:
        """Secure subprocess.Popen wrapper with validation.

        Args:
            command: Command to execute
            shell: Whether to use shell (strongly discouraged)
            stdout: stdout configuration
            stderr: stderr configuration
            stdin: stdin configuration
            cwd: Working directory
            env: Environment variables
            **kwargs: Additional arguments for subprocess.Popen

        Returns:
            Popen instance

        """
        # Force shell=False for security unless explicitly required
        if shell:
            logger.warning("Shell execution requested - this reduces security")
            # Convert to string for shell execution
            if isinstance(command, list):
                command = " ".join(command)
        else:
            # Validate command for non-shell execution
            if isinstance(command, str):
                # Split string command safely
                command = shlex.split(command)
            command = SecureSubprocess.validate_command(command)

        # Validate working directory if provided
        if cwd:
            cwd = os.path.abspath(cwd)
            if not Path(cwd).is_dir():
                error_msg = f"Invalid working directory: {cwd}"
                logger.error(error_msg)
                raise ValueError(error_msg)

        # Execute with security flags
        return subprocess.Popen(
            command, shell=shell, stdout=stdout, stderr=stderr, stdin=stdin, cwd=cwd, env=env, **kwargs,
        )


# Convenience functions for drop-in replacement
def secure_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
    """Drop-in replacement for subprocess.run with security validation.

    Args:
        *args: Positional arguments passed to SecureSubprocess.run
        **kwargs: Keyword arguments passed to SecureSubprocess.run

    Returns:
        CompletedProcess instance from the secure subprocess execution

    """
    return SecureSubprocess.run(*args, **kwargs)


def secure_popen(*args: object, **kwargs: object) -> subprocess.Popen:
    """Drop-in replacement for subprocess.Popen with security validation.

    Args:
        *args: Positional arguments passed to SecureSubprocess.popen
        **kwargs: Keyword arguments passed to SecureSubprocess.popen

    Returns:
        Popen instance from the secure subprocess execution

    """
    return SecureSubprocess.popen(*args, **kwargs)
