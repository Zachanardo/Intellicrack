"""Production tests for AI Common Types.

Tests shared type definitions and dataclass functionality.

Copyright (C) 2025 Zachary Flint
"""

from datetime import datetime, timedelta

import pytest

from intellicrack.ai.common_types import ExecutionResult


class TestExecutionResult:
    """Test ExecutionResult dataclass."""

    def test_execution_result_creation(self) -> None:
        """ExecutionResult created with all required fields."""
        result = ExecutionResult(
            success=True,
            output="Test output",
            error="",
            exit_code=0,
            runtime_ms=150,
        )

        assert result.success is True
        assert result.output == "Test output"
        assert result.error == ""
        assert result.exit_code == 0
        assert result.runtime_ms == 150
        assert result.timestamp is not None

    def test_execution_result_auto_timestamp(self) -> None:
        """ExecutionResult auto-generates timestamp if not provided."""
        before = datetime.now()
        result = ExecutionResult(
            success=False,
            output="",
            error="Error message",
            exit_code=1,
            runtime_ms=50,
        )
        after = datetime.now()

        assert result.timestamp is not None
        assert before <= result.timestamp <= after + timedelta(seconds=1)

    def test_execution_result_with_explicit_timestamp(self) -> None:
        """ExecutionResult respects explicitly provided timestamp."""
        explicit_time = datetime(2025, 1, 1, 12, 0, 0)
        result = ExecutionResult(
            success=True,
            output="Output",
            error="",
            exit_code=0,
            runtime_ms=100,
            timestamp=explicit_time,
        )

        assert result.timestamp == explicit_time

    def test_execution_result_failure_scenario(self) -> None:
        """ExecutionResult correctly represents failure scenarios."""
        result = ExecutionResult(
            success=False,
            output="Partial output",
            error="Command failed",
            exit_code=127,
            runtime_ms=25,
        )

        assert result.success is False
        assert result.exit_code != 0
        assert result.error != ""

    def test_execution_result_zero_runtime(self) -> None:
        """ExecutionResult handles instant execution correctly."""
        result = ExecutionResult(
            success=True,
            output="Instant",
            error="",
            exit_code=0,
            runtime_ms=0,
        )

        assert result.runtime_ms == 0

    def test_execution_result_long_runtime(self) -> None:
        """ExecutionResult handles long execution times."""
        result = ExecutionResult(
            success=True,
            output="Long process",
            error="",
            exit_code=0,
            runtime_ms=5000,
        )

        assert result.runtime_ms == 5000
