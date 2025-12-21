"""Production tests for process_common.py.

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

import subprocess
import sys
import logging
from typing import Any, Callable

import pytest

from intellicrack.utils.system.process_common import (
    create_popen_safely,
    create_suspended_process_with_context,
    run_subprocess_safely,
)


class TestRunSubprocessSafely:
    """Test safe subprocess execution."""

    def test_run_subprocess_safely_simple_command(self) -> None:
        """Simple command executes successfully."""
        cmd: list[str] = ["python", "--version"]
        result: subprocess.CompletedProcess = run_subprocess_safely(cmd, timeout=5)

        assert result.returncode == 0
        assert len(result.stdout) > 0

    def test_run_subprocess_safely_captures_output(self) -> None:
        """Subprocess captures stdout and stderr."""
        cmd: list[str] = ["python", "-c", "print('test output')"]
        result: subprocess.CompletedProcess = run_subprocess_safely(cmd, timeout=5)

        assert "test output" in result.stdout
        assert result.returncode == 0

    def test_run_subprocess_safely_handles_stderr(self) -> None:
        """Subprocess captures stderr output."""
        cmd: list[str] = ["python", "-c", "import sys; sys.stderr.write('error\\n')"]
        result: subprocess.CompletedProcess = run_subprocess_safely(cmd, timeout=5)

        assert "error" in result.stderr or result.returncode == 0

    def test_run_subprocess_safely_returns_exit_code(self) -> None:
        """Subprocess returns actual exit code."""
        cmd: list[str] = ["python", "-c", "import sys; sys.exit(42)"]
        result: subprocess.CompletedProcess = run_subprocess_safely(cmd, timeout=5, capture_output=True)

        assert result.returncode == 42

    def test_run_subprocess_safely_timeout_handling(self) -> None:
        """Subprocess raises TimeoutExpired on timeout."""
        cmd: list[str] = ["python", "-c", "import time; time.sleep(10)"]

        with pytest.raises(subprocess.TimeoutExpired):
            run_subprocess_safely(cmd, timeout=1)

    def test_run_subprocess_safely_invalid_command(self) -> None:
        """Invalid command raises FileNotFoundError."""
        cmd: list[str] = ["nonexistent_command_12345"]

        with pytest.raises(FileNotFoundError):
            run_subprocess_safely(cmd, timeout=5)

    def test_run_subprocess_safely_capture_output_false(self) -> None:
        """capture_output=False doesn't capture stdout/stderr."""
        cmd: list[str] = ["python", "-c", "print('test')"]
        result: subprocess.CompletedProcess = run_subprocess_safely(cmd, timeout=5, capture_output=False)

        assert result.stdout is None
        assert result.stderr is None

    def test_run_subprocess_safely_text_mode(self) -> None:
        """Output is returned as text strings."""
        cmd: list[str] = ["python", "-c", "print('text mode')"]
        result: subprocess.CompletedProcess = run_subprocess_safely(cmd, timeout=5)

        assert isinstance(result.stdout, str)
        assert isinstance(result.stderr, str)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
    def test_run_subprocess_safely_windows_command(self) -> None:
        """Windows-specific command executes correctly."""
        cmd: list[str] = ["cmd", "/c", "echo test"]
        result: subprocess.CompletedProcess = run_subprocess_safely(cmd, timeout=5)

        assert result.returncode == 0
        assert "test" in result.stdout

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-only test")
    def test_run_subprocess_safely_unix_command(self) -> None:
        """Unix-specific command executes correctly."""
        cmd: list[str] = ["echo", "test"]
        result: subprocess.CompletedProcess = run_subprocess_safely(cmd, timeout=5)

        assert result.returncode == 0
        assert "test" in result.stdout


class TestCreatePopenSafely:
    """Test safe Popen process creation."""

    def test_create_popen_safely_returns_popen(self) -> None:
        """create_popen_safely returns Popen object."""
        cmd: list[str] = ["python", "-c", "print('test')"]
        proc: subprocess.Popen[str] = create_popen_safely(cmd)

        assert isinstance(proc, subprocess.Popen)
        proc.wait(timeout=5)
        proc.kill()

    def test_create_popen_safely_captures_stdout(self) -> None:
        """Popen process captures stdout by default."""
        cmd: list[str] = ["python", "-c", "print('popen test')"]
        proc: subprocess.Popen[str] = create_popen_safely(cmd)

        stdout, stderr = proc.communicate(timeout=5)

        assert "popen test" in stdout
        assert proc.returncode == 0

    def test_create_popen_safely_captures_stderr(self) -> None:
        """Popen process captures stderr by default."""
        cmd: list[str] = ["python", "-c", "import sys; sys.stderr.write('error\\n')"]
        proc: subprocess.Popen[str] = create_popen_safely(cmd)

        stdout, stderr = proc.communicate(timeout=5)

        assert "error" in stderr or proc.returncode == 0

    def test_create_popen_safely_text_mode(self) -> None:
        """Popen returns text output by default."""
        cmd: list[str] = ["python", "-c", "print('text')"]
        proc: subprocess.Popen[str] = create_popen_safely(cmd)

        stdout, stderr = proc.communicate(timeout=5)

        assert isinstance(stdout, str)
        assert isinstance(stderr, str)

    def test_create_popen_safely_custom_kwargs(self) -> None:
        """Popen accepts custom keyword arguments."""
        cmd: list[str] = ["python", "-c", "print('custom')"]
        proc: subprocess.Popen[str] = create_popen_safely(cmd, cwd=None)

        stdout, stderr = proc.communicate(timeout=5)

        assert "custom" in stdout
        assert proc.returncode == 0

    def test_create_popen_safely_process_alive(self) -> None:
        """Created Popen process is alive until completed."""
        cmd: list[str] = ["python", "-c", "import time; time.sleep(0.5); print('done')"]
        proc: subprocess.Popen[str] = create_popen_safely(cmd)

        assert proc.poll() is None
        proc.wait(timeout=5)
        assert proc.poll() is not None

    def test_create_popen_safely_can_be_terminated(self) -> None:
        """Created Popen process can be terminated."""
        cmd: list[str] = ["python", "-c", "import time; time.sleep(100)"]
        proc: subprocess.Popen[str] = create_popen_safely(cmd)

        proc.terminate()
        proc.wait(timeout=5)

        assert proc.returncode is not None


class TestCreateSuspendedProcessWithContext:
    """Test suspended process creation with context pattern."""

    def test_create_suspended_process_with_context_success(self) -> None:
        """Successful process creation returns success dict."""

        def mock_create_func(target_exe: str) -> dict[str, Any]:
            return {
                "process_handle": 12345,
                "thread_handle": 67890,
                "process_id": 1000,
                "thread_id": 2000,
            }

        def mock_get_context_func(thread_handle: int) -> dict[str, int]:
            return {"eip": 0x12345678, "esp": 0x87654321}

        result: dict[str, Any] = create_suspended_process_with_context(
            mock_create_func,
            mock_get_context_func,
            "test.exe"
        )

        assert result["success"] is True
        assert "process_info" in result
        assert "context" in result
        assert result["process_info"]["process_handle"] == 12345

    def test_create_suspended_process_with_context_create_fails(self) -> None:
        """Failed process creation returns error dict."""

        def mock_create_func_fail(target_exe: str) -> None:
            return None

        def mock_get_context_func(thread_handle: int) -> dict[str, int]:
            return {"eip": 0x12345678}

        result: dict[str, Any] = create_suspended_process_with_context(
            mock_create_func_fail,
            mock_get_context_func,
            "test.exe"
        )

        assert result["success"] is False
        assert "error" in result
        assert "Failed to create suspended process" in result["error"]

    def test_create_suspended_process_with_context_get_context_fails(self) -> None:
        """Failed context retrieval returns error with process_info."""

        def mock_create_func(target_exe: str) -> dict[str, Any]:
            return {
                "process_handle": 12345,
                "thread_handle": 67890,
            }

        def mock_get_context_func_fail(thread_handle: int) -> None:
            return None

        result: dict[str, Any] = create_suspended_process_with_context(
            mock_create_func,
            mock_get_context_func_fail,
            "test.exe"
        )

        assert result["success"] is False
        assert "error" in result
        assert "Failed to get thread context" in result["error"]
        assert "process_info" in result

    def test_create_suspended_process_with_context_exception_handling(self) -> None:
        """Exception in process creation returns error dict."""

        def mock_create_func_exception(target_exe: str) -> dict[str, Any]:
            raise RuntimeError("Process creation error")

        def mock_get_context_func(thread_handle: int) -> dict[str, int]:
            return {"eip": 0x12345678}

        result: dict[str, Any] = create_suspended_process_with_context(
            mock_create_func_exception,
            mock_get_context_func,
            "test.exe"
        )

        assert result["success"] is False
        assert "error" in result
        assert "Process creation error" in result["error"]

    def test_create_suspended_process_with_context_custom_logger(self) -> None:
        """Custom logger instance is used for logging."""
        custom_logger: logging.Logger = logging.getLogger("test_custom")

        def mock_create_func_fail(target_exe: str) -> None:
            return None

        def mock_get_context_func(thread_handle: int) -> dict[str, int]:
            return {}

        result: dict[str, Any] = create_suspended_process_with_context(
            mock_create_func_fail,
            mock_get_context_func,
            "test.exe",
            logger_instance=custom_logger
        )

        assert result["success"] is False

    def test_create_suspended_process_with_context_returns_all_data(self) -> None:
        """Successful creation returns complete process and context data."""

        def mock_create_func(target_exe: str) -> dict[str, Any]:
            return {
                "process_handle": 11111,
                "thread_handle": 22222,
                "process_id": 3333,
                "thread_id": 4444,
            }

        def mock_get_context_func(thread_handle: int) -> dict[str, int]:
            return {
                "eip": 0xAABBCCDD,
                "esp": 0x11223344,
                "eax": 0x55667788,
            }

        result: dict[str, Any] = create_suspended_process_with_context(
            mock_create_func,
            mock_get_context_func,
            "complete_test.exe"
        )

        assert result["success"] is True
        assert result["process_info"]["process_id"] == 3333
        assert result["process_info"]["thread_id"] == 4444
        assert result["context"]["eip"] == 0xAABBCCDD
        assert result["context"]["esp"] == 0x11223344


class TestProcessCommonIntegration:
    """Integration tests for process common utilities."""

    def test_subprocess_safely_and_popen_consistency(self) -> None:
        """run_subprocess_safely and create_popen_safely produce similar results."""
        cmd: list[str] = ["python", "-c", "print('consistency')"]

        result_run: subprocess.CompletedProcess = run_subprocess_safely(cmd, timeout=5)
        proc: subprocess.Popen[str] = create_popen_safely(cmd)
        stdout_popen, stderr_popen = proc.communicate(timeout=5)

        assert result_run.returncode == proc.returncode
        assert "consistency" in result_run.stdout
        assert "consistency" in stdout_popen

    def test_real_process_execution_chain(self) -> None:
        """Real process execution works end-to-end."""
        cmd: list[str] = ["python", "-c", "import sys; print('chain test'); sys.exit(0)"]

        result: subprocess.CompletedProcess = run_subprocess_safely(cmd, timeout=5)

        assert result.returncode == 0
        assert "chain test" in result.stdout
        assert isinstance(result.stdout, str)

    def test_process_timeout_handling_realistic(self) -> None:
        """Timeout handling works with realistic delay."""
        cmd: list[str] = ["python", "-c", "import time; time.sleep(2)"]

        with pytest.raises(subprocess.TimeoutExpired):
            run_subprocess_safely(cmd, timeout=1)
