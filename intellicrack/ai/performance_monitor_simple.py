"""Production performance monitor for AI operations.
"""

import logging
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from functools import wraps
from typing import Any

logger = logging.getLogger(__name__)


class PerformanceMonitor:
    """Real-time performance monitoring for AI operations."""

    def __init__(self):
        self.metrics = defaultdict(list)
        self.operation_counts = defaultdict(int)
        self.error_counts = defaultdict(int)
        self.lock = threading.Lock()
        self.start_times = {}

    def start_operation(self, operation_name: str) -> str:
        """Start timing an operation."""
        operation_id = f"{operation_name}_{time.time()}_{threading.current_thread().ident}"
        with self.lock:
            self.start_times[operation_id] = time.time()
        return operation_id

    def end_operation(self, operation_id: str, operation_name: str, success: bool = True):
        """End timing an operation and record metrics."""
        end_time = time.time()
        with self.lock:
            if operation_id in self.start_times:
                duration = end_time - self.start_times[operation_id]
                self.metrics[operation_name].append({
                    "duration": duration,
                    "timestamp": end_time,
                    "success": success,
                })
                self.operation_counts[operation_name] += 1
                if not success:
                    self.error_counts[operation_name] += 1
                del self.start_times[operation_id]

                # Keep only last 1000 metrics per operation
                if len(self.metrics[operation_name]) > 1000:
                    self.metrics[operation_name] = self.metrics[operation_name][-1000:]

    def get_stats(self, operation_name: str) -> dict[str, Any]:
        """Get performance statistics for an operation."""
        with self.lock:
            if operation_name not in self.metrics:
                return {}

            durations = [m["duration"] for m in self.metrics[operation_name]]
            if not durations:
                return {}

            return {
                "count": len(durations),
                "avg_duration": sum(durations) / len(durations),
                "min_duration": min(durations),
                "max_duration": max(durations),
                "error_rate": self.error_counts[operation_name] / self.operation_counts[operation_name],
                "total_operations": self.operation_counts[operation_name],
            }


class AsyncPerformanceMonitor:
    """Async performance monitoring for concurrent operations."""

    def __init__(self):
        self.active_operations = {}
        self.completed_operations = deque(maxlen=10000)
        self.lock = threading.Lock()

    async def monitor_operation(self, operation_name: str, coroutine):
        """Monitor an async operation."""
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
            result = None
            success = False
        finally:
            end_time = time.time()
            with self.lock:
                if operation_id in self.active_operations:
                    op_info = self.active_operations.pop(operation_id)
                    self.completed_operations.append({
                        "name": operation_name,
                        "duration": end_time - op_info["start_time"],
                        "success": success,
                        "timestamp": end_time,
                    })

        return result

    def get_active_count(self) -> int:
        """Get number of currently active operations."""
        with self.lock:
            return len(self.active_operations)


# Global instances
_performance_monitor = PerformanceMonitor()
_async_monitor = AsyncPerformanceMonitor()


def profile_ai_operation(operation_name: str = None):
    """Decorator for profiling AI operations with real performance tracking."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
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

        return wrapper
    return decorator


def get_performance_monitor() -> PerformanceMonitor:
    """Get the real performance monitor instance."""
    return _performance_monitor


def get_async_monitor() -> AsyncPerformanceMonitor:
    """Get the real async performance monitor instance."""
    return _async_monitor
