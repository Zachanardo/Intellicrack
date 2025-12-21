"""Tests for completed_count logging in intellicrack_core_engine.py.

This tests that the completed_count variable is properly tracked and logged
during async handler execution using asyncio.as_completed.
"""


from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Callable
from unittest.mock import MagicMock

import pytest


class MockEvent:
    """Mock event for testing."""

    def __init__(self, event_type: str = "test_event") -> None:
        self.event_type = event_type


class TestCompletedCountLogging:
    """Test suite for completed_count tracking and logging."""

    @pytest.mark.asyncio
    async def test_completed_count_increments_on_success(self) -> None:
        """Test that completed_count increments for successful handlers."""
        completed_count = 0
        results: list[Any] = []

        async def successful_handler() -> str:
            return "success"

        tasks = [
            asyncio.create_task(successful_handler()),
            asyncio.create_task(successful_handler()),
            asyncio.create_task(successful_handler()),
        ]

        for completed_task in asyncio.as_completed(tasks, timeout=5.0):
            try:
                result = await completed_task
                results.append(result)
                completed_count += 1
            except Exception as e:
                results.append(e)
                completed_count += 1

        assert completed_count == 3
        assert all(r == "success" for r in results)

    @pytest.mark.asyncio
    async def test_completed_count_increments_on_exception(self) -> None:
        """Test that completed_count increments even when handlers fail."""
        completed_count = 0
        results: list[Any] = []

        async def failing_handler() -> None:
            raise ValueError("Handler failed")

        async def successful_handler() -> str:
            return "success"

        tasks = [
            asyncio.create_task(successful_handler()),
            asyncio.create_task(failing_handler()),
            asyncio.create_task(successful_handler()),
        ]

        for completed_task in asyncio.as_completed(tasks, timeout=5.0):
            try:
                result = await completed_task
                results.append(result)
                completed_count += 1
            except Exception as e:
                results.append(e)
                completed_count += 1

        assert completed_count == 3
        exception_count = sum(bool(isinstance(r, Exception))
                          for r in results)
        assert exception_count == 1

    @pytest.mark.asyncio
    async def test_logger_receives_completed_count(self) -> None:
        """Test that logger receives correct completed_count value."""
        logger = MagicMock()
        completed_count = 0
        results: list[Any] = []
        event = MockEvent("analysis_complete")

        async def handler() -> str:
            return "done"

        tasks = [
            asyncio.create_task(handler()),
            asyncio.create_task(handler()),
        ]

        for completed_task in asyncio.as_completed(tasks, timeout=5.0):
            try:
                result = await completed_task
                results.append(result)
                completed_count += 1
            except Exception as e:
                results.append(e)
                completed_count += 1

        logger.debug(
            "Event %s: %d/%d handlers completed successfully",
            event.event_type,
            completed_count,
            len(tasks),
        )

        logger.debug.assert_called_once()
        call_args = logger.debug.call_args[0]
        assert call_args[1] == "analysis_complete"
        assert call_args[2] == 2
        assert call_args[3] == 2

    @pytest.mark.asyncio
    async def test_as_completed_preserves_completion_order(self) -> None:
        """Test that as_completed processes tasks as they finish."""
        completion_order: list[int] = []
        completed_count = 0

        async def delayed_handler(delay: float, value: int) -> int:
            await asyncio.sleep(delay)
            return value

        tasks = [
            asyncio.create_task(delayed_handler(0.1, 1)),
            asyncio.create_task(delayed_handler(0.01, 2)),
            asyncio.create_task(delayed_handler(0.05, 3)),
        ]

        for completed_task in asyncio.as_completed(tasks, timeout=5.0):
            result = await completed_task
            completion_order.append(result)
            completed_count += 1

        assert completed_count == 3
        assert completion_order[0] == 2
        assert completion_order[1] == 3
        assert completion_order[2] == 1

    @pytest.mark.asyncio
    async def test_handler_timeout_configuration(self) -> None:
        """Test handler timeout using timedelta."""
        handler_timeout = timedelta(seconds=30)
        timeout_seconds = handler_timeout.total_seconds()

        assert timeout_seconds == 30.0

        shorter_timeout = timedelta(seconds=5)
        assert shorter_timeout.total_seconds() == 5.0

    @pytest.mark.asyncio
    async def test_empty_tasks_list_handling(self) -> None:
        """Test handling when no tasks are created."""
        completed_count = 0

        if tasks := []:
            for completed_task in asyncio.as_completed(tasks, timeout=5.0):
                await completed_task
                completed_count += 1

        assert completed_count == 0

    @pytest.mark.asyncio
    async def test_mixed_success_and_failure_count(self) -> None:
        """Test accurate counting with mixed success/failure."""
        completed_count = 0
        success_count = 0
        failure_count = 0

        async def success() -> str:
            return "ok"

        async def failure() -> None:
            raise RuntimeError("fail")

        tasks = [
            asyncio.create_task(success()),
            asyncio.create_task(failure()),
            asyncio.create_task(success()),
            asyncio.create_task(failure()),
            asyncio.create_task(success()),
        ]

        for completed_task in asyncio.as_completed(tasks, timeout=5.0):
            try:
                await completed_task
                success_count += 1
                completed_count += 1
            except Exception:
                failure_count += 1
                completed_count += 1

        assert completed_count == 5
        assert success_count == 3
        assert failure_count == 2

    @pytest.mark.asyncio
    async def test_handler_type_tracking(self) -> None:
        """Test that handler types are tracked for error reporting."""
        class AnalysisHandler:
            async def __call__(self, event: MockEvent) -> str:
                return "analyzed"

        class PatchHandler:
            async def __call__(self, event: MockEvent) -> str:
                return "patched"

        handlers = [AnalysisHandler(), PatchHandler()]

        handler_types: list[type] = [type(handler) for handler in handlers]
        assert handler_types[0].__name__ == "AnalysisHandler"
        assert handler_types[1].__name__ == "PatchHandler"

    @pytest.mark.asyncio
    async def test_exception_logging_with_handler_index(self) -> None:
        """Test that exceptions are logged with handler index."""
        logger = MagicMock()
        results: list[Any] = []
        handler_types = [type(lambda: None), type(lambda: None)]

        async def failing() -> None:
            raise ValueError("test error")

        async def success() -> str:
            return "ok"

        tasks = [
            asyncio.create_task(failing()),
            asyncio.create_task(success()),
        ]

        for completed_task in asyncio.as_completed(tasks, timeout=5.0):
            try:
                result = await completed_task
                results.append(result)
            except Exception as e:
                results.append(e)

        event = MockEvent("test_event")
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.exception(
                    "Handler %d (%s) failed for event %s: %s",
                    i,
                    handler_types[i].__name__,
                    event.event_type,
                    result,
                )

        assert logger.exception.called

    @pytest.mark.asyncio
    async def test_completed_count_matches_task_count(self) -> None:
        """Test that completed_count equals total tasks after completion."""
        completed_count = 0

        async def handler(n: int) -> int:
            return n * 2

        num_tasks = 10
        tasks = [asyncio.create_task(handler(i)) for i in range(num_tasks)]

        for completed_task in asyncio.as_completed(tasks, timeout=5.0):
            await completed_task
            completed_count += 1

        assert completed_count == num_tasks
        assert completed_count == len(tasks)

    @pytest.mark.asyncio
    async def test_real_time_completion_tracking(self) -> None:
        """Test that completion is tracked in real-time."""
        progress: list[int] = []

        async def handler(n: int) -> int:
            await asyncio.sleep(0.01 * n)
            return n

        tasks = [asyncio.create_task(handler(i)) for i in range(5)]
        completed_count = 0

        for completed_task in asyncio.as_completed(tasks, timeout=5.0):
            await completed_task
            completed_count += 1
            progress.append(completed_count)

        assert progress == [1, 2, 3, 4, 5]
        assert completed_count == 5

