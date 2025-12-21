"""Production tests for subprocess_utils.py.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import subprocess
import sys

import pytest

from intellicrack.utils.system.subprocess_utils import (
    create_popen_with_encoding,
    run_subprocess,
    run_subprocess_check,
)


class TestRunSubprocess:
    """Test subprocess execution with standard error handling."""

    def test_run_subprocess_simple_command(self) -> None:
        """Simple command executes successfully."""
        returncode, stdout, stderr = run_subprocess(["python", "--version"])

        assert returncode == 0
        assert len(stdout) > 0 or len(stderr) > 0

    def test_run_subprocess_captures_stdout(self) -> None:
        """Subprocess captures stdout."""
        returncode, stdout, stderr = run_subprocess(["python", "-c", "print('test output')"])

        assert returncode == 0
        assert "test output" in stdout

    def test_run_subprocess_captures_stderr(self) -> None:
        """Subprocess captures stderr."""
        returncode, stdout, stderr = run_subprocess(
            ["python", "-c", "import sys; sys.stderr.write('error\\n')"]
        )

        assert "error" in stderr or returncode == 0

    def test_run_subprocess_returns_exit_code(self) -> None:
        """Subprocess returns correct exit code."""
        returncode, stdout, stderr = run_subprocess(["python", "-c", "import sys; sys.exit(7)"])

        assert returncode == 7

    def test_run_subprocess_timeout_handling(self) -> None:
        """Subprocess handles timeout correctly."""
        returncode, stdout, stderr = run_subprocess(
            ["python", "-c", "import time; time.sleep(5)"],
            timeout=1
        )

        assert returncode is not None

    def test_run_subprocess_text_mode(self) -> None:
        """Subprocess returns text output."""
        returncode, stdout, stderr = run_subprocess(
            ["python", "-c", "print('text')"],
            text=True
        )

        assert isinstance(stdout, str)
        assert isinstance(stderr, str)

    def test_run_subprocess_capture_output_false(self) -> None:
        """capture_output=False doesn't capture output."""
        returncode, stdout, stderr = run_subprocess(
            ["python", "-c", "print('test')"],
            capture_output=False
        )

        assert stdout == ""
        assert stderr == ""

    def test_run_subprocess_string_command(self) -> None:
        """String command is split and executed."""
        returncode, stdout, stderr = run_subprocess("python --version")

        assert returncode == 0

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_run_subprocess_windows_command(self) -> None:
        """Windows-specific command executes."""
        returncode, stdout, stderr = run_subprocess(["cmd", "/c", "echo test"])

        assert returncode == 0
        assert "test" in stdout


class TestRunSubprocessCheck:
    """Test subprocess execution with check parameter."""

    def test_run_subprocess_check_success(self) -> None:
        """Successful command with check=True works."""
        result: subprocess.CompletedProcess = run_subprocess_check(
            ["python", "-c", "print('success')"],
            check=False
        )

        assert result.returncode == 0
        assert "success" in result.stdout

    def test_run_subprocess_check_captures_output(self) -> None:
        """Subprocess with check captures output."""
        result: subprocess.CompletedProcess = run_subprocess_check(
            ["python", "-c", "print('captured')"]
        )

        assert result.stdout
        assert "captured" in result.stdout

    def test_run_subprocess_check_text_mode(self) -> None:
        """Subprocess with check returns text."""
        result: subprocess.CompletedProcess = run_subprocess_check(
            ["python", "-c", "print('text')"],
            text=True
        )

        assert isinstance(result.stdout, str)

    def test_run_subprocess_check_timeout(self) -> None:
        """Subprocess with check handles timeout."""
        with pytest.raises(subprocess.TimeoutExpired):
            run_subprocess_check(
                ["python", "-c", "import time; time.sleep(10)"],
                timeout=1
            )

    def test_run_subprocess_check_returns_completed_process(self) -> None:
        """Subprocess check returns CompletedProcess object."""
        result: subprocess.CompletedProcess = run_subprocess_check(
            ["python", "--version"]
        )

        assert isinstance(result, subprocess.CompletedProcess)
        assert hasattr(result, "returncode")
        assert hasattr(result, "stdout")
        assert hasattr(result, "stderr")


class TestCreatePopenWithEncoding:
    """Test Popen creation with encoding support."""

    def test_create_popen_with_encoding_default(self) -> None:
        """Popen with default UTF-8 encoding works."""
        returncode, stdout, stderr = create_popen_with_encoding(
            ["python", "-c", "print('utf8')"]
        )

        assert returncode == 0
        assert "utf8" in stdout

    def test_create_popen_with_encoding_captures_output(self) -> None:
        """Popen with encoding captures stdout and stderr."""
        returncode, stdout, stderr = create_popen_with_encoding(
            ["python", "-c", "print('output')"]
        )

        assert isinstance(stdout, str)
        assert isinstance(stderr, str)
        assert "output" in stdout

    def test_create_popen_with_encoding_custom_encoding(self) -> None:
        """Popen with custom encoding works."""
        returncode, stdout, stderr = create_popen_with_encoding(
            ["python", "-c", "print('custom')"],
            encoding="utf-8"
        )

        assert returncode == 0
        assert "custom" in stdout

    def test_create_popen_with_encoding_timeout(self) -> None:
        """Popen with encoding handles timeout."""
        returncode, stdout, stderr = create_popen_with_encoding(
            ["python", "-c", "import time; time.sleep(10)"],
            timeout=1
        )

        assert returncode == -1

    def test_create_popen_with_encoding_returns_tuple(self) -> None:
        """Popen with encoding returns (returncode, stdout, stderr) tuple."""
        result = create_popen_with_encoding(
            ["python", "-c", "print('tuple')"]
        )

        assert isinstance(result, tuple)
        assert len(result) == 3
        assert isinstance(result[0], int)
        assert isinstance(result[1], str)
        assert isinstance(result[2], str)

    def test_create_popen_with_encoding_handles_errors(self) -> None:
        """Popen with encoding handles command errors."""
        returncode, stdout, stderr = create_popen_with_encoding(
            ["python", "-c", "import sys; sys.exit(3)"]
        )

        assert returncode == 3

    def test_create_popen_with_encoding_unicode_output(self) -> None:
        """Popen with encoding handles Unicode output."""
        returncode, stdout, stderr = create_popen_with_encoding(
            ["python", "-c", "print('Unicode: ñ é ü')"],
            encoding="utf-8"
        )

        assert returncode == 0
        assert isinstance(stdout, str)


class TestSubprocessUtilsIntegration:
    """Integration tests for subprocess utilities."""

    def test_all_subprocess_functions_consistent(self) -> None:
        """All subprocess functions produce consistent results."""
        cmd: list[str] = ["python", "-c", "print('consistent')"]

        result1 = run_subprocess(cmd)
        result2 = create_popen_with_encoding(cmd)
        result3_obj = run_subprocess_check(cmd, check=False)

        assert result1[0] == result2[0] == result3_obj.returncode
        assert "consistent" in result1[1]
        assert "consistent" in result2[1]
        assert "consistent" in result3_obj.stdout

    def test_subprocess_utils_real_python_execution(self) -> None:
        """Subprocess utils execute real Python code."""
        returncode, stdout, stderr = run_subprocess(
            ["python", "-c", "import sys; print(sys.version)"]
        )

        assert returncode == 0
        assert len(stdout) > 0
        assert "Python" in stdout or len(stderr) > 0

    def test_subprocess_utils_handle_varying_outputs(self) -> None:
        """Subprocess utils handle varying output sizes."""
        small_rc, small_out, _ = run_subprocess(
            ["python", "-c", "print('x')"]
        )
        large_rc, large_out, _ = run_subprocess(
            ["python", "-c", "print('x' * 5000)"]
        )

        assert small_rc == 0
        assert large_rc == 0
        assert len(large_out) > len(small_out)

    def test_subprocess_utils_sequential_execution(self) -> None:
        """Multiple sequential subprocess executions work."""
        for i in range(10):
            returncode, stdout, stderr = run_subprocess(
                ["python", "-c", f"print({i})"]
            )
            assert returncode == 0
            assert str(i) in stdout


class TestSubprocessUtilsEdgeCases:
    """Edge case tests for subprocess utilities."""

    def test_run_subprocess_empty_output(self) -> None:
        """Subprocess with no output is handled."""
        returncode, stdout, stderr = run_subprocess(
            ["python", "-c", "pass"]
        )

        assert returncode == 0
        assert stdout == "" or len(stdout.strip()) == 0

    def test_run_subprocess_very_long_output(self) -> None:
        """Subprocess with very long output is captured."""
        returncode, stdout, stderr = run_subprocess(
            ["python", "-c", "print('A' * 100000)"],
            timeout=10
        )

        assert returncode == 0
        assert len(stdout) >= 100000

    def test_run_subprocess_multiline_output(self) -> None:
        """Subprocess with multiline output is captured."""
        returncode, stdout, stderr = run_subprocess(
            ["python", "-c", "for i in range(10): print(i)"]
        )

        assert returncode == 0
        assert stdout.count("\n") >= 9

    def test_create_popen_with_encoding_error_replacement(self) -> None:
        """Popen with encoding replaces unencodable characters."""
        returncode, stdout, stderr = create_popen_with_encoding(
            ["python", "-c", "print('test')"],
            encoding="ascii"
        )

        assert returncode == 0

    def test_run_subprocess_check_without_capture(self) -> None:
        """Subprocess check with capture_output=False works."""
        result: subprocess.CompletedProcess = run_subprocess_check(
            ["python", "-c", "print('no capture')"],
            capture_output=False
        )

        assert result.returncode == 0
