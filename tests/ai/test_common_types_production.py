"""Production tests for AI common types module.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from datetime import datetime, timedelta

import pytest

from intellicrack.ai.common_types import ExecutionResult


class TestExecutionResult:
    """Test ExecutionResult dataclass functionality."""

    def test_execution_result_successful_creation(self) -> None:
        """ExecutionResult creates successful result with all fields."""
        result = ExecutionResult(
            success=True,
            output="License check bypassed successfully",
            error="",
            exit_code=0,
            runtime_ms=1250,
        )

        assert result.success is True
        assert result.output == "License check bypassed successfully"
        assert result.error == ""
        assert result.exit_code == 0
        assert result.runtime_ms == 1250
        assert result.timestamp is not None
        assert isinstance(result.timestamp, datetime)

    def test_execution_result_failed_creation(self) -> None:
        """ExecutionResult creates failed result with error details."""
        result = ExecutionResult(
            success=False,
            output="",
            error="Failed to locate license validation routine",
            exit_code=1,
            runtime_ms=500,
        )

        assert result.success is False
        assert result.output == ""
        assert result.error == "Failed to locate license validation routine"
        assert result.exit_code == 1
        assert result.runtime_ms == 500

    def test_execution_result_auto_timestamp_generation(self) -> None:
        """ExecutionResult auto-generates timestamp when not provided."""
        before = datetime.now()
        result = ExecutionResult(
            success=True,
            output="Keygen executed",
            error="",
            exit_code=0,
            runtime_ms=100,
        )
        after = datetime.now()

        assert result.timestamp is not None
        assert before <= result.timestamp <= after

    def test_execution_result_custom_timestamp(self) -> None:
        """ExecutionResult accepts custom timestamp."""
        custom_time = datetime(2025, 1, 15, 10, 30, 0)
        result = ExecutionResult(
            success=True,
            output="Test",
            error="",
            exit_code=0,
            runtime_ms=100,
            timestamp=custom_time,
        )

        assert result.timestamp == custom_time

    def test_execution_result_with_script_output(self) -> None:
        """ExecutionResult handles multi-line script output."""
        script_output = """Found license check at 0x401000
Patched JNZ to JMP at 0x401015
License validation bypassed
Binary saved to cracked.exe"""

        result = ExecutionResult(
            success=True,
            output=script_output,
            error="",
            exit_code=0,
            runtime_ms=2500,
        )

        assert "Found license check" in result.output
        assert "Patched JNZ to JMP" in result.output
        assert "License validation bypassed" in result.output
        assert result.success is True

    def test_execution_result_with_complex_error(self) -> None:
        """ExecutionResult handles complex error messages."""
        error_msg = """Traceback (most recent call last):
  File "keygen.py", line 42, in generate
    key = rsa_keygen(algorithm_params)
  File "crypto.py", line 18, in rsa_keygen
    raise ValueError("Invalid modulus size")
ValueError: Invalid modulus size"""

        result = ExecutionResult(
            success=False,
            output="",
            error=error_msg,
            exit_code=1,
            runtime_ms=50,
        )

        assert result.success is False
        assert "Traceback" in result.error
        assert "ValueError: Invalid modulus size" in result.error

    def test_execution_result_zero_runtime(self) -> None:
        """ExecutionResult handles instantaneous execution."""
        result = ExecutionResult(
            success=True,
            output="Cache hit",
            error="",
            exit_code=0,
            runtime_ms=0,
        )

        assert result.runtime_ms == 0
        assert result.success is True

    def test_execution_result_long_runtime(self) -> None:
        """ExecutionResult handles long-running operations."""
        result = ExecutionResult(
            success=True,
            output="VMProtect analysis complete",
            error="",
            exit_code=0,
            runtime_ms=300000,
        )

        assert result.runtime_ms == 300000
        assert result.runtime_ms >= 300000

    def test_execution_result_exit_code_variations(self) -> None:
        """ExecutionResult handles various exit codes."""
        result_success = ExecutionResult(
            success=True, output="OK", error="", exit_code=0, runtime_ms=100
        )
        result_generic_fail = ExecutionResult(
            success=False, output="", error="Error", exit_code=1, runtime_ms=50
        )
        result_specific_fail = ExecutionResult(
            success=False, output="", error="Access denied", exit_code=127, runtime_ms=25
        )

        assert result_success.exit_code == 0
        assert result_generic_fail.exit_code == 1
        assert result_specific_fail.exit_code == 127

    def test_execution_result_timestamp_ordering(self) -> None:
        """ExecutionResult timestamps maintain chronological order."""
        result1 = ExecutionResult(
            success=True, output="Step 1", error="", exit_code=0, runtime_ms=100
        )

        import time
        time.sleep(0.01)

        result2 = ExecutionResult(
            success=True, output="Step 2", error="", exit_code=0, runtime_ms=100
        )

        assert result1.timestamp is not None
        assert result2.timestamp is not None
        assert result2.timestamp > result1.timestamp

    def test_execution_result_partial_success(self) -> None:
        """ExecutionResult handles partial success scenarios."""
        result = ExecutionResult(
            success=True,
            output="2 of 3 license checks bypassed",
            error="Warning: Third check may still validate",
            exit_code=0,
            runtime_ms=1500,
        )

        assert result.success is True
        assert result.error != ""
        assert result.exit_code == 0

    def test_execution_result_empty_strings(self) -> None:
        """ExecutionResult handles empty output and error strings."""
        result = ExecutionResult(
            success=True,
            output="",
            error="",
            exit_code=0,
            runtime_ms=50,
        )

        assert result.output == ""
        assert result.error == ""
        assert result.success is True

    def test_execution_result_unicode_content(self) -> None:
        """ExecutionResult handles unicode characters in output."""
        result = ExecutionResult(
            success=True,
            output="Analysis complete ✓\nKey generated: АБВ-123-ЯЮЭ",
            error="",
            exit_code=0,
            runtime_ms=200,
        )

        assert "✓" in result.output
        assert "АБВ" in result.output

    def test_execution_result_timing_accuracy(self) -> None:
        """ExecutionResult runtime values represent actual execution time."""
        fast_result = ExecutionResult(
            success=True, output="Quick", error="", exit_code=0, runtime_ms=50
        )
        slow_result = ExecutionResult(
            success=True, output="Slow", error="", exit_code=0, runtime_ms=5000
        )

        assert fast_result.runtime_ms < slow_result.runtime_ms
        assert slow_result.runtime_ms - fast_result.runtime_ms >= 4950

    def test_execution_result_comparison_by_success(self) -> None:
        """ExecutionResult can be analyzed for success patterns."""
        results = [
            ExecutionResult(True, "OK", "", 0, 100),
            ExecutionResult(False, "", "Fail", 1, 50),
            ExecutionResult(True, "OK", "", 0, 200),
            ExecutionResult(False, "", "Fail", 1, 75),
        ]

        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]

        assert len(successful) == 2
        assert len(failed) == 2
        assert all(r.exit_code == 0 for r in successful)
        assert all(r.exit_code == 1 for r in failed)

    def test_execution_result_negative_exit_code(self) -> None:
        """ExecutionResult handles negative exit codes."""
        result = ExecutionResult(
            success=False,
            output="",
            error="Process terminated by signal",
            exit_code=-1,
            runtime_ms=100,
        )

        assert result.exit_code == -1
        assert result.success is False
