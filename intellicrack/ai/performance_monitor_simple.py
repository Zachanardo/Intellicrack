"""Production performance monitor for AI operations.

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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable, Coroutine
from functools import wraps
from typing import Any, TypeVar


logger = logging.getLogger(__name__)

T = TypeVar("T")


class PerformanceMonitor:
    """Real-time performance monitoring for AI operations."""

    def __init__(self) -> None:
        """Initialize performance monitor with metric tracking."""
        self.metrics: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.operation_counts: dict[str, int] = defaultdict(int)
        self.error_counts: dict[str, int] = defaultdict(int)
        self.lock: threading.Lock = threading.Lock()
        self.start_times: dict[str, float] = {}

    def start_operation(self, operation_name: str) -> str:
        """Start timing an operation.

        Args:
            operation_name: The name of the operation to time.

        Returns:
            A unique operation ID for tracking.

        """
        operation_id = f"{operation_name}_{time.time()}_{threading.current_thread().ident}"
        with self.lock:
            self.start_times[operation_id] = time.time()
        return operation_id

    def end_operation(self, operation_id: str, operation_name: str, success: bool = True) -> None:
        """End timing an operation and record metrics.

        Args:
            operation_id: The unique operation ID returned by start_operation.
            operation_name: The name of the operation being timed.
            success: Whether the operation completed successfully.

        """
        end_time = time.time()
        with self.lock:
            if operation_id in self.start_times:
                duration = end_time - self.start_times[operation_id]
                self.metrics[operation_name].append(
                    {
                        "duration": duration,
                        "timestamp": end_time,
                        "success": success,
                    },
                )
                self.operation_counts[operation_name] += 1
                if not success:
                    self.error_counts[operation_name] += 1
                del self.start_times[operation_id]

                if len(self.metrics[operation_name]) > 1000:
                    self.metrics[operation_name] = self.metrics[operation_name][-1000:]

    def get_stats(self, operation_name: str) -> dict[str, Any]:
        """Get performance statistics for an operation.

        Args:
            operation_name: The name of the operation to retrieve statistics for.

        Returns:
            A dictionary containing count, average duration, min/max duration,
            error rate, and total operations for the specified operation.

        """
        with self.lock:
            if operation_name not in self.metrics:
                return {}

            if durations := [m["duration"] for m in self.metrics[operation_name]]:
                return {
                    "count": len(durations),
                    "avg_duration": sum(durations) / len(durations),
                    "min_duration": min(durations),
                    "max_duration": max(durations),
                    "error_rate": self.error_counts[operation_name] / self.operation_counts[operation_name],
                    "total_operations": self.operation_counts[operation_name],
                }
            else:
                return {}


class AsyncPerformanceMonitor:
    """Async performance monitoring for concurrent operations."""

    def __init__(self) -> None:
        """Initialize async performance monitor with operation tracking."""
        self.active_operations: dict[str, dict[str, Any]] = {}
        self.completed_operations: deque[dict[str, Any]] = deque(maxlen=10000)
        self.lock: threading.Lock = threading.Lock()

    async def monitor_operation(self, operation_name: str, coroutine: Coroutine[Any, Any, T]) -> T:
        """Monitor an async operation.

        Args:
            operation_name: The name of the operation being monitored.
            coroutine: The coroutine to monitor.

        Returns:
            The result of the coroutine execution.

        """
        start_time = time.time()
        operation_id = f"{operation_name}_{start_time}_{id(coroutine)}"

        with self.lock:
            self.active_operations[operation_id] = {
                "name": operation_name,
                "start_time": start_time,
            }

        try:
            result = await coroutine
            success = True
        except Exception as e:
            logger.error(f"Operation {operation_name} failed: {e}")
            result = None  # type: ignore[assignment]
            success = False
        finally:
            end_time = time.time()
            with self.lock:
                if operation_id in self.active_operations:
                    op_info = self.active_operations.pop(operation_id)
                    self.completed_operations.append(
                        {
                            "name": operation_name,
                            "duration": end_time - op_info["start_time"],
                            "success": success,
                            "timestamp": end_time,
                        },
                    )

        return result

    def get_active_count(self) -> int:
        """Get number of currently active operations.

        Returns:
            The count of currently active async operations.

        """
        with self.lock:
            return len(self.active_operations)


_performance_monitor: PerformanceMonitor = PerformanceMonitor()
_async_monitor: AsyncPerformanceMonitor = AsyncPerformanceMonitor()


def profile_ai_operation(
    operation_name: str | None = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Profile AI operations with real performance tracking using a decorator.

    Args:
        operation_name: Optional name for the operation. If not provided,
            the function module and name will be used.

    Returns:
        A decorator function that wraps the target function with performance monitoring.

    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: object, **kwargs: object) -> T:
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            operation_id = _performance_monitor.start_operation(op_name)

            try:
                result = func(*args, **kwargs)
                _performance_monitor.end_operation(operation_id, op_name, success=True)
                return result
            except Exception as e:
                _performance_monitor.end_operation(operation_id, op_name, success=False)
                logger.error(f"Operation {op_name} failed: {e}")
                raise

        return wrapper  # type: ignore[return-value]

    return decorator


def get_performance_monitor() -> PerformanceMonitor:
    """Get the real performance monitor instance.

    Returns:
        The global PerformanceMonitor instance.

    """
    return _performance_monitor


def get_async_monitor() -> AsyncPerformanceMonitor:
    """Get the real async performance monitor instance.

    Returns:
        The global AsyncPerformanceMonitor instance.

    """
    return _async_monitor
