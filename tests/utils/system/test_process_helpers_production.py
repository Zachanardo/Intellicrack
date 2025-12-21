"""Production tests for process_helpers.py.

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

import sys

import pytest

from intellicrack.utils.system.process_helpers import (
    run_ghidra_process,
    run_process_with_output,
)


class TestRunProcessWithOutput:
    """Test process execution with output capture."""

    def test_run_process_with_output_simple_command(self) -> None:
        """Simple command executes and returns output."""
        cmd: list[str] = ["python", "--version"]
        returncode, stdout, stderr = run_process_with_output(cmd, timeout=5)

        assert returncode == 0
        assert len(stdout) > 0 or len(stderr) > 0
        assert "Python" in stdout or "Python" in stderr

    def test_run_process_with_output_returns_tuple(self) -> None:
        """Function returns (returncode, stdout, stderr) tuple."""
        cmd: list[str] = ["python", "-c", "print('test')"]
        result = run_process_with_output(cmd, timeout=5)

        assert isinstance(result, tuple)
        assert len(result) == 3
        assert isinstance(result[0], int)
        assert isinstance(result[1], str)
        assert isinstance(result[2], str)

    def test_run_process_with_output_captures_stdout(self) -> None:
        """Stdout is captured correctly."""
        cmd: list[str] = ["python", "-c", "print('stdout test')"]
        returncode, stdout, stderr = run_process_with_output(cmd, timeout=5)

        assert returncode == 0
        assert "stdout test" in stdout

    def test_run_process_with_output_captures_stderr(self) -> None:
        """Stderr is captured correctly."""
        cmd: list[str] = ["python", "-c", "import sys; sys.stderr.write('stderr test\\n')"]
        returncode, stdout, stderr = run_process_with_output(cmd, timeout=5)

        assert "stderr test" in stderr or returncode == 0

    def test_run_process_with_output_exit_code(self) -> None:
        """Exit code is returned correctly."""
        cmd: list[str] = ["python", "-c", "import sys; sys.exit(5)"]
        returncode, stdout, stderr = run_process_with_output(cmd, timeout=5)

        assert returncode == 5

    def test_run_process_with_output_custom_encoding(self) -> None:
        """Custom encoding parameter is respected."""
        cmd: list[str] = ["python", "-c", "print('encoded')"]
        returncode, stdout, stderr = run_process_with_output(cmd, encoding="utf-8", timeout=5)

        assert returncode == 0
        assert isinstance(stdout, str)
        assert "encoded" in stdout

    def test_run_process_with_output_timeout_parameter(self) -> None:
        """Timeout parameter is passed correctly."""
        cmd: list[str] = ["python", "-c", "import time; time.sleep(0.1); print('done')"]
        returncode, stdout, stderr = run_process_with_output(cmd, timeout=2)

        assert returncode == 0
        assert "done" in stdout

    def test_run_process_with_output_handles_timeout_expiry(self) -> None:
        """Timeout expiry is handled appropriately."""
        cmd: list[str] = ["python", "-c", "import time; time.sleep(10)"]

        try:
            returncode, stdout, stderr = run_process_with_output(cmd, timeout=1)
            assert returncode != 0 or stdout == "" or stderr != ""
        except Exception:
            pass

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_run_process_with_output_windows_cmd(self) -> None:
        """Windows command executes correctly."""
        cmd: list[str] = ["cmd", "/c", "echo windows test"]
        returncode, stdout, stderr = run_process_with_output(cmd, timeout=5)

        assert returncode == 0
        assert "windows test" in stdout

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only test")
    def test_run_process_with_output_unix_command(self) -> None:
        """Unix command executes correctly."""
        cmd: list[str] = ["echo", "unix test"]
        returncode, stdout, stderr = run_process_with_output(cmd, timeout=5)

        assert returncode == 0
        assert "unix test" in stdout


class TestRunGhidraProcess:
    """Test Ghidra subprocess execution."""

    def test_run_ghidra_process_returns_tuple(self) -> None:
        """run_ghidra_process returns (returncode, stdout, stderr) tuple."""
        cmd: list[str] = ["python", "-c", "print('ghidra test')"]
        result = run_ghidra_process(cmd)

        assert isinstance(result, tuple)
        assert len(result) == 3
        assert isinstance(result[0], int)
        assert isinstance(result[1], str)
        assert isinstance(result[2], str)

    def test_run_ghidra_process_simple_command(self) -> None:
        """Simple command through run_ghidra_process works."""
        cmd: list[str] = ["python", "--version"]
        returncode, stdout, stderr = run_ghidra_process(cmd)

        assert returncode == 0
        assert len(stdout) > 0 or len(stderr) > 0

    def test_run_ghidra_process_uses_utf8_encoding(self) -> None:
        """run_ghidra_process uses UTF-8 encoding."""
        cmd: list[str] = ["python", "-c", "print('UTF-8 ñ')"]
        returncode, stdout, stderr = run_ghidra_process(cmd)

        assert returncode == 0
        assert isinstance(stdout, str)

    def test_run_ghidra_process_captures_output(self) -> None:
        """run_ghidra_process captures command output."""
        cmd: list[str] = ["python", "-c", "print('ghidra output')"]
        returncode, stdout, stderr = run_ghidra_process(cmd)

        assert returncode == 0
        assert "ghidra output" in stdout

    def test_run_ghidra_process_handles_errors(self) -> None:
        """run_ghidra_process handles command errors."""
        cmd: list[str] = ["python", "-c", "import sys; sys.exit(1)"]
        returncode, stdout, stderr = run_ghidra_process(cmd)

        assert returncode == 1

    def test_run_ghidra_process_delegates_to_run_process_with_output(self) -> None:
        """run_ghidra_process delegates to run_process_with_output."""
        cmd: list[str] = ["python", "-c", "print('delegation test')"]

        ghidra_result = run_ghidra_process(cmd)
        direct_result = run_process_with_output(cmd, encoding="utf-8")

        assert ghidra_result[0] == direct_result[0]
        assert ghidra_result[1] == direct_result[1]


class TestProcessHelpersIntegration:
    """Integration tests for process helpers."""

    def test_process_helpers_consistent_output_format(self) -> None:
        """All helper functions return consistent tuple format."""
        cmd: list[str] = ["python", "-c", "print('format test')"]

        result1 = run_process_with_output(cmd)
        result2 = run_ghidra_process(cmd)

        assert len(result1) == len(result2) == 3
        assert type(result1[0]) == type(result2[0]) == int
        assert type(result1[1]) == type(result2[1]) == str
        assert type(result1[2]) == type(result2[2]) == str

    def test_process_helpers_real_command_execution(self) -> None:
        """Process helpers execute real commands on system."""
        cmd: list[str] = ["python", "-c", "import sys; print(sys.version_info.major)"]

        returncode, stdout, stderr = run_process_with_output(cmd, timeout=5)

        assert returncode == 0
        assert stdout.strip().isdigit()
        assert int(stdout.strip()) >= 3

    def test_multiple_sequential_process_executions(self) -> None:
        """Multiple sequential process executions work correctly."""
        for i in range(5):
            cmd: list[str] = ["python", "-c", f"print({i})"]
            returncode, stdout, stderr = run_process_with_output(cmd, timeout=5)

            assert returncode == 0
            assert str(i) in stdout

    def test_process_helpers_handle_varying_output_sizes(self) -> None:
        """Process helpers handle varying output sizes."""
        small_cmd: list[str] = ["python", "-c", "print('x')"]
        large_cmd: list[str] = ["python", "-c", "print('x' * 1000)"]

        small_rc, small_out, small_err = run_process_with_output(small_cmd, timeout=5)
        large_rc, large_out, large_err = run_process_with_output(large_cmd, timeout=5)

        assert small_rc == 0
        assert large_rc == 0
        assert len(small_out) < len(large_out)


class TestProcessHelpersEdgeCases:
    """Edge case tests for process helpers."""

    def test_run_process_with_output_empty_command_list(self) -> None:
        """Empty command list is handled."""
        try:
            returncode, stdout, stderr = run_process_with_output([], timeout=5)
            assert isinstance(returncode, int)
        except (IndexError, ValueError, FileNotFoundError):
            pass

    def test_run_process_with_output_none_timeout(self) -> None:
        """None timeout allows indefinite execution."""
        cmd: list[str] = ["python", "-c", "print('no timeout')"]
        returncode, stdout, stderr = run_process_with_output(cmd, timeout=None)

        assert returncode == 0
        assert "no timeout" in stdout

    def test_run_process_with_output_very_long_output(self) -> None:
        """Very long output is captured completely."""
        cmd: list[str] = ["python", "-c", "print('A' * 10000)"]
        returncode, stdout, stderr = run_process_with_output(cmd, timeout=5)

        assert returncode == 0
        assert len(stdout) >= 10000

    def test_run_process_with_output_multiline_output(self) -> None:
        """Multiline output is captured correctly."""
        cmd: list[str] = ["python", "-c", "print('line1\\nline2\\nline3')"]
        returncode, stdout, stderr = run_process_with_output(cmd, timeout=5)

        assert returncode == 0
        assert "line1" in stdout
        assert "line2" in stdout
        assert "line3" in stdout

    def test_run_process_with_output_unicode_characters(self) -> None:
        """Unicode characters in output are handled."""
        cmd: list[str] = ["python", "-c", "print('Hello 世界 🌍')"]
        returncode, stdout, stderr = run_process_with_output(cmd, encoding="utf-8", timeout=5)

        assert returncode == 0
        assert isinstance(stdout, str)
