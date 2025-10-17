"""Provide process execution helper functions.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


def run_process_with_output(cmd: list[str], encoding: str = "utf-8", timeout: int | None = None) -> tuple[int, str, str]:
    """Run a process and capture stdout/stderr.

    Args:
        cmd: Command list to execute
        encoding: Text encoding for output
        timeout: Optional timeout in seconds

    Returns:
        tuple: (return_code, stdout, stderr)

    """
    from .subprocess_utils import create_popen_with_encoding

    return create_popen_with_encoding(cmd, encoding, timeout)


def run_ghidra_process(cmd: list[str]) -> tuple[int, str, str]:
    """Run Ghidra subprocess with standard configuration.

    Args:
        cmd: Ghidra command list

    Returns:
        tuple: (return_code, stdout, stderr)

    """
    return run_process_with_output(cmd, encoding="utf-8")
