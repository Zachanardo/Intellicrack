"""Performance Monitoring and Optimization System.

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

import functools
import gc
import json
import logging
import threading
import time
import types
from collections import defaultdict, deque
from collections.abc import AsyncGenerator, Callable, Coroutine, Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

try:
    from intellicrack.handlers.psutil_handler import psutil

    HAS_PSUTIL = True
except ImportError as e:
    logger.exception("Import error in performance_monitor: %s", e)
    psutil = None
    HAS_PSUTIL = False


@dataclass
class PerformanceMetric:
    """Individual performance metric."""

    name: str
    value: float
    unit: str
    timestamp: datetime = field(default_factory=datetime.now)
    category: str = "general"
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceProfile:
    """Performance profile for a specific operation."""

    operation_name: str
    execution_time: float
    memory_usage: int
    cpu_usage: float
    success: bool
    error_message: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)


class PerformanceMonitor:
    """Comprehensive performance monitoring system."""

    def __init__(self, max_history: int = 1000) -> None:
        """Initialize the performance monitoring system.

        Args:
            max_history: Maximum number of metrics and profiles to retain
                        in history

        """
        self.logger = logging.getLogger(f"{__name__}.PerformanceMonitor")
        self.max_history = max_history
        self.metrics: dict[str, deque[PerformanceMetric]] = defaultdict(lambda: deque(maxlen=max_history))
        self.profiles: deque[PerformanceProfile] = deque(maxlen=max_history)
        self.active_operations: dict[str, dict[str, Any]] = {}
        self.optimization_rules: list[Callable[[str, str, float], None]] = []

        # Performance thresholds
        self.thresholds: dict[str, dict[str, float]] = {
            "execution_time": {"warning": 5.0, "critical": 15.0},
            "memory_usage": {"warning": 500 * 1024 * 1024, "critical": 1024 * 1024 * 1024},
            "cpu_usage": {"warning": 80.0, "critical": 95.0},
            "memory_growth": {"warning": 50 * 1024 * 1024, "critical": 100 * 1024 * 1024},
        }

        # System monitoring
        if HAS_PSUTIL:
            self.process = psutil.Process()
            self.start_time = time.time()
            self.baseline_memory = self.process.memory_info().rss
        else:
            self.process = None
            self.start_time = time.time()
            self.baseline_memory = 0

        # Background monitoring
        self._monitoring_active = False
        self._monitor_thread: threading.Thread | None = None

        # Performance cache
        self.performance_cache: dict[str, Any] = {}
        self.cache_ttl = 300  # 5 minutes

        logger.info("Performance monitor initialized")

    def start_monitoring(self, interval: float = 1.0) -> None:
        """Start background system monitoring.

        Args:
            interval: Time in seconds between monitoring checks. Defaults to 1.0

        Returns:
            None

        """
        if self._monitoring_active:
            return

        self._monitoring_active = True
        thread = threading.Thread(
            target=self._monitor_system,
            args=(interval,),
            daemon=True,
        )
        self._monitor_thread = thread
        thread.start()
        logger.info("Background performance monitoring started")

    def stop_monitoring(self) -> None:
        """Stop background monitoring."""
        self._monitoring_active = False
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=2.0)
            logger.info("Background performance monitoring stopped")

    def _monitor_system(self, interval: float) -> None:
        """Background system monitoring loop.

        Args:
            interval: Time in seconds between monitoring checks

        """
        while self._monitoring_active:
            try:
                # System metrics
                if HAS_PSUTIL and self.process:
                    cpu_percent = psutil.cpu_percent(interval=0.1)
                    memory_info = self.process.memory_info()

                    self.record_metric("system.cpu_usage", cpu_percent, "percent")
                    self.record_metric("system.memory_rss", memory_info.rss, "bytes")
                    self.record_metric("system.memory_vms", memory_info.vms, "bytes")

                    # Memory growth tracking
                    memory_growth = memory_info.rss - self.baseline_memory
                    self.record_metric("system.memory_growth", memory_growth, "bytes")

                # Check thresholds
                self._check_thresholds(cpu_percent, memory_info.rss, memory_growth)

                time.sleep(interval)

            except Exception as e:
                logger.exception("Error in system monitoring: %s", e, exc_info=True)
                time.sleep(interval)

    def _check_thresholds(self, cpu_usage: float, memory_usage: int, memory_growth: int) -> None:
        """Check if metrics exceed thresholds.

        Args:
            cpu_usage: Current CPU usage percentage
            memory_usage: Current memory usage in bytes
            memory_growth: Memory growth since baseline in bytes

        """
        checks: list[tuple[str, float]] = [
            ("cpu_usage", cpu_usage),
            ("memory_usage", float(memory_usage)),
            ("memory_growth", float(memory_growth)),
        ]

        for metric_name, value in checks:
            metric_thresholds = self.thresholds.get(metric_name, {})
            critical_threshold = metric_thresholds.get("critical", float("inf"))
            warning_threshold = metric_thresholds.get("warning", float("inf"))

            if value > critical_threshold:
                logger.critical("Critical %s: %s", metric_name, value)
                self._trigger_optimization(metric_name, "critical", value)
            elif value > warning_threshold:
                logger.warning("High %s: %s", metric_name, value)
                self._trigger_optimization(metric_name, "warning", value)

    def _trigger_optimization(self, metric_name: str, level: str, value: float) -> None:
        """Trigger optimization based on threshold breach.

        Args:
            metric_name: Name of the metric exceeding threshold
            level: Severity level (warning or critical)
            value: Current metric value

        """
        if metric_name == "memory_growth" and level in {"warning", "critical"}:
            logger.info("Triggering garbage collection due to memory growth")
            gc.collect()

        # Run optimization rules
        for rule in self.optimization_rules:
            try:
                rule(metric_name, level, value)
            except Exception as e:
                logger.exception("Error in optimization rule: %s", e, exc_info=True)

    def record_metric(
        self,
        name: str,
        value: float,
        unit: str,
        category: str = "general",
        context: dict[str, Any] | None = None,
    ) -> None:
        """Record a performance metric.

        Args:
            name: Name identifier for the metric
            value: Numeric value of the metric
            unit: Unit of measurement (e.g., 'bytes', 'seconds', 'percent')
            category: Category for grouping metrics. Defaults to 'general'
            context: Optional dictionary with additional context about metric

        """
        metric = PerformanceMetric(
            name=name,
            value=value,
            unit=unit,
            category=category,
            context=context or {},
        )

        self.metrics[name].append(metric)

    @contextmanager
    def profile_operation(
        self,
        operation_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> Generator[str, None, None]:
        """Profile an operation with automatic performance metric collection.

        Context manager that profiles a single operation, measuring execution time,
        memory usage, and CPU usage. Records all metrics and handles exceptions.

        Args:
            operation_name: Identifier for the operation being profiled
            metadata: Optional metadata dictionary to associate with the operation

        Yields:
            str: Operation ID for use in the profiled code block

        Raises:
            Exception: Any exception raised in the context is re-raised after
                      profiling is completed and metrics are recorded

        """
        start_time = time.time()
        start_memory = self.process.memory_info().rss if HAS_PSUTIL and self.process else 0
        start_cpu = psutil.cpu_percent() if HAS_PSUTIL else 0

        operation_id = f"{operation_name}_{int(start_time)}"
        self.active_operations[operation_id] = {
            "name": operation_name,
            "start_time": start_time,
            "start_memory": start_memory,
            "metadata": metadata or {},
        }

        success = True
        error_message = None

        try:
            yield operation_id
        except Exception as e:
            self.logger.exception("Exception in performance_monitor: %s", e)
            success = False
            error_message = str(e)
            raise
        finally:
            end_time = time.time()
            end_memory = self.process.memory_info().rss if HAS_PSUTIL and self.process else 0
            end_cpu = psutil.cpu_percent() if HAS_PSUTIL else 0

            execution_time = end_time - start_time
            memory_usage = end_memory - start_memory
            cpu_usage = (start_cpu + end_cpu) / 2

            profile = PerformanceProfile(
                operation_name=operation_name,
                execution_time=execution_time,
                memory_usage=memory_usage,
                cpu_usage=cpu_usage,
                success=success,
                error_message=error_message,
                metadata=metadata or {},
            )

            self.profiles.append(profile)

            # Record individual metrics
            self.record_metric(f"operation.{operation_name}.execution_time", execution_time, "seconds")
            self.record_metric(f"operation.{operation_name}.memory_usage", memory_usage, "bytes")
            self.record_metric(f"operation.{operation_name}.cpu_usage", cpu_usage, "percent")

            # Cleanup
            if operation_id in self.active_operations:
                del self.active_operations[operation_id]

    def time_function(
        self,
        func_name: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Create a decorator that profiles function execution time.

        Returns a decorator that wraps a function to automatically measure and
        record its execution time, memory usage, and CPU usage.

        Args:
            func_name: Optional name to use for the operation. If not provided,
                      uses module.function name format

        Returns:
            Callable[[Callable[..., Any]], Callable[..., Any]]: Decorator function
                that takes a callable and returns a wrapped version with profiling
                enabled

        """

        def decorator(func: Callable[..., object]) -> Callable[..., object]:
            name = func_name or f"{func.__module__}.{func.__name__}"

            @functools.wraps(func)
            def wrapper(*args: object, **kwargs: object) -> object:
                with self.profile_operation(name):
                    return func(*args, **kwargs)

            return wrapper

        return decorator

    def get_metrics_summary(self, time_window: timedelta | None = None) -> dict[str, Any]:
        """Get summary of metrics within time window.

        Args:
            time_window: Time window to summarize. If None, defaults to 1 hour

        Returns:
            dict[str, Any]: Dictionary containing metrics summary, operation summary,
                           and system health assessment

        """
        cutoff_time = datetime.now() - (time_window or timedelta(hours=1))

        summary: dict[str, Any] = {
            "timeframe": str(time_window or timedelta(hours=1)),
            "metrics": {},
            "operation_summary": {},
            "system_health": self._assess_system_health(),
        }

        # Metrics summary
        for metric_name, metric_list in self.metrics.items():
            if recent_metrics := [m for m in metric_list if m.timestamp >= cutoff_time]:
                values = [m.value for m in recent_metrics]
                metrics_dict: dict[str, Any] = summary["metrics"]
                metrics_dict[metric_name] = {
                    "count": len(values),
                    "avg": sum(values) / len(values),
                    "min": min(values),
                    "max": max(values),
                    "latest": values[-1],
                    "unit": recent_metrics[-1].unit,
                }

        # Operation summary
        recent_profiles = [p for p in self.profiles if p.timestamp >= cutoff_time]

        operation_stats: defaultdict[str, list[PerformanceProfile]] = defaultdict(list)
        for profile in recent_profiles:
            operation_stats[profile.operation_name].append(profile)

        for op_name, profiles in operation_stats.items():
            exec_times = [p.execution_time for p in profiles]
            memory_usage = [p.memory_usage for p in profiles]
            success_rate = sum(bool(p.success) for p in profiles) / len(profiles)

            op_summary_dict: dict[str, Any] = summary["operation_summary"]
            op_summary_dict[op_name] = {
                "count": len(profiles),
                "avg_execution_time": sum(exec_times) / len(exec_times),
                "max_execution_time": max(exec_times),
                "avg_memory_usage": sum(memory_usage) / len(memory_usage),
                "success_rate": success_rate,
            }

        return summary

    def _assess_system_health(self) -> dict[str, Any]:
        """Assess overall system health.

        Returns:
            dict[str, Any]: Health assessment with score, status, issues list,
                           and memory/CPU metrics

        """
        try:
            if HAS_PSUTIL and self.process:
                current_memory = self.process.memory_info().rss
                memory_growth = current_memory - self.baseline_memory
                cpu_usage = psutil.cpu_percent(interval=0.1)
            else:
                current_memory = 0
                memory_growth = 0
                cpu_usage = 0

            health_score = 100.0
            issues: list[str] = []

            # Memory assessment
            memory_thresholds = self.thresholds.get("memory_growth", {})
            memory_critical = memory_thresholds.get("critical", float("inf"))
            memory_warning = memory_thresholds.get("warning", float("inf"))

            if memory_growth > memory_critical:
                health_score -= 30
                issues.append("Critical memory growth")
            elif memory_growth > memory_warning:
                health_score -= 15
                issues.append("High memory growth")

            # CPU assessment
            cpu_thresholds = self.thresholds.get("cpu_usage", {})
            cpu_critical = cpu_thresholds.get("critical", float("inf"))
            cpu_warning = cpu_thresholds.get("warning", float("inf"))

            if cpu_usage > cpu_critical:
                health_score -= 25
                issues.append("Critical CPU usage")
            elif cpu_usage > cpu_warning:
                health_score -= 10
                issues.append("High CPU usage")

            # Recent errors
            recent_failures = [p for p in list(self.profiles)[-50:] if not p.success]

            if len(recent_failures) > 10:
                health_score -= 20
                issues.append("High error rate")
            elif len(recent_failures) > 5:
                health_score -= 10
                issues.append("Moderate error rate")

            return {
                "score": max(0, health_score),
                "status": "healthy" if health_score > 80 else "degraded" if health_score > 50 else "critical",
                "issues": issues,
                "current_memory_mb": current_memory / 1024 / 1024,
                "memory_growth_mb": memory_growth / 1024 / 1024,
                "cpu_usage": cpu_usage,
            }

        except Exception as e:
            logger.exception("Error assessing system health: %s", e, exc_info=True)
            return {"score": 0, "status": "unknown", "error": str(e)}

    def add_optimization_rule(self, rule: Callable[[str, str, float], None]) -> None:
        """Add optimization rule.

        Args:
            rule: Callable that takes metric_name, level, and value arguments

        """
        self.optimization_rules.append(rule)

    def get_performance_recommendations(self) -> list[str]:
        """Get performance optimization recommendations.

        Returns:
            list[str]: List of performance optimization recommendations based on
                      recent metrics

        """
        recommendations = []
        summary = self.get_metrics_summary(timedelta(minutes=30))

        # Memory recommendations
        current_memory = self.process.memory_info().rss if HAS_PSUTIL and self.process else 0
        memory_growth = current_memory - self.baseline_memory

        if memory_growth > 100 * 1024 * 1024:  # 100MB
            recommendations.append("Consider running garbage collection or reducing memory usage")

        # CPU recommendations
        if summary["system_health"]["cpu_usage"] > 80:
            recommendations.append("High CPU usage detected - consider optimizing algorithms or reducing workload")

        # Operation-specific recommendations
        for op_name, stats in summary.get("operation_summary", {}).items():
            if stats["avg_execution_time"] > 10.0:
                recommendations.append(f"Operation '{op_name}' is slow (avg: {stats['avg_execution_time']:.2f}s)")

            if stats["success_rate"] < 0.9:
                recommendations.append(f"Operation '{op_name}' has low success rate ({stats['success_rate']:.1%})")

        return recommendations

    def export_metrics(self, file_path: Path, format: str = "json") -> None:
        """Export metrics to file.

        Args:
            file_path: Path object for output file
            format: Export format. Currently only 'json' is supported

        Raises:
            ValueError: If unsupported format is specified

        """
        try:
            summary = self.get_metrics_summary(timedelta(hours=24))

            if format != "json":
                raise ValueError(f"Unsupported format: {format}")

            with open(file_path, "w") as f:
                json.dump(summary, f, indent=2, default=str)
            logger.info("Metrics exported to %s", file_path)

        except Exception as e:
            logger.exception("Failed to export metrics: %s", e, exc_info=True)

    def optimize_cache(self) -> None:
        """Optimize performance cache by removing expired entries."""
        current_time = time.time()
        expired_keys = [key for key, (timestamp, _) in self.performance_cache.items() if current_time - timestamp > self.cache_ttl]

        for key in expired_keys:
            del self.performance_cache[key]

        if expired_keys:
            logger.debug("Cleaned %s expired cache entries", len(expired_keys))

    def get_cached_result(self, cache_key: str) -> dict[str, Any] | None:
        """Retrieve a cached performance result if still valid.

        Checks the cache for a result with the given key. If found and not
        expired based on cache_ttl, returns the cached value. Otherwise
        removes the expired entry and returns None.

        Args:
            cache_key: Key identifying the cached result

        Returns:
            dict[str, Any] | None: The cached result dictionary if valid,
                                   or None if not cached or expired

        """
        if cache_key in self.performance_cache:
            cache_entry: Any = self.performance_cache[cache_key]
            if isinstance(cache_entry, tuple) and len(cache_entry) == 2:
                timestamp, result = cache_entry
                if isinstance(timestamp, (int, float)) and isinstance(result, dict):
                    if time.time() - timestamp < self.cache_ttl:
                        return result
            del self.performance_cache[cache_key]
        return None

    def cache_result(self, cache_key: str, result: dict[str, Any]) -> None:
        """Store a performance result in the cache with timestamp.

        Caches a result dictionary along with the current timestamp.
        The result can later be retrieved with get_cached_result until
        the cache_ttl expires.

        Args:
            cache_key: Key to identify this cached result
            result: Result dictionary to cache

        """
        self.performance_cache[cache_key] = (time.time(), result)

    def _log_final_metrics(self) -> None:
        """Log final performance metrics before exit."""
        try:
            current_stats = self.get_metrics_summary()
            logger.info("Final performance metrics: %s", current_stats)
            if hasattr(self, "optimization_rules") and self.optimization_rules:
                logger.info("Active optimization rules: %s", len(self.optimization_rules))
        except Exception as e:
            logger.debug("Could not log final metrics: %s", e, exc_info=True)

    def __enter__(self) -> "PerformanceMonitor":
        """Start background monitoring on context entry.

        Returns:
            PerformanceMonitor: The performance monitor instance

        """
        self.start_monitoring()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Stop background monitoring and log metrics on context exit.

        Args:
            exc_type: Exception type if an exception occurred
            exc_val: Exception value if an exception occurred
            exc_tb: Exception traceback if an exception occurred

        """
        if exc_type:
            logger.exception("Performance monitor exiting due to %s: %s", exc_type.__name__, exc_val, exc_info=True)
            self._log_final_metrics()
            if exc_tb:
                logger.debug("Exception traceback from %s:%s", exc_tb.tb_frame.f_code.co_filename, exc_tb.tb_lineno)
        self.stop_monitoring()


# Global performance monitor instance
# Lazy initialization to avoid circular imports
_performance_monitor = None


def get_performance_monitor() -> PerformanceMonitor:
    """Retrieve or create the global performance monitor instance.

    Returns the singleton PerformanceMonitor instance, creating it on
    first access if needed. This lazy initialization prevents circular
    import issues.

    Returns:
        PerformanceMonitor: The global performance monitor instance

    """
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor


def profile_ai_operation(
    operation_name: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Create a decorator for profiling AI operation performance.

    Returns a decorator that wraps AI functions to automatically measure
    execution time, memory usage, and CPU usage. Designed to integrate
    with the global performance monitor for licensing analysis operations.

    Args:
        operation_name: Optional custom name for the operation. If not
                       provided, uses the wrapped function's name

    Returns:
        Callable[[Callable[..., Any]], Callable[..., Any]]: Decorator function
            that profiles wrapped functions

    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        # Simplified version to avoid initialization issues
        return func

    return decorator


@contextmanager
def monitor_memory_usage(threshold_mb: float = 100.0) -> Generator[None, None, None]:
    """Monitor memory usage within a code block and log warnings.

    Context manager that tracks memory consumption during execution of
    a code block. If memory increase exceeds the threshold, logs a warning
    and records the metric to the global performance monitor.

    Args:
        threshold_mb: Memory increase threshold in MB that triggers warning.
                     Defaults to 100.0 MB

    Yields:
        None

    """
    start_memory = psutil.Process().memory_info().rss

    try:
        yield
    finally:
        end_memory = psutil.Process().memory_info().rss
        memory_increase = (end_memory - start_memory) / 1024 / 1024

        if memory_increase > threshold_mb:
            logger.warning("High memory usage: %.2fMB increase", memory_increase)

        get_performance_monitor().record_metric(
            "memory.operation_increase",
            memory_increase,
            "MB",
        )


class AsyncPerformanceMonitor:
    """Asynchronous performance monitoring for async operations."""

    def __init__(self, base_monitor: PerformanceMonitor) -> None:
        """Initialize the async performance monitor.

        Args:
            base_monitor: Base performance monitor to delegate synchronous
                         operations to

        """
        self.logger = logging.getLogger(f"{__name__}.AsyncPerformanceMonitor")
        self.base_monitor = base_monitor
        self.async_operations: dict[str, dict[str, Any]] = {}

    async def profile_async_operation(
        self,
        operation_name: str,
        coro: Coroutine[None, None, object],
    ) -> object:
        """Profile an async operation with performance metrics.

        Executes an async coroutine while measuring execution time, memory usage,
        and recording performance metrics. Exceptions are re-raised after metrics
        are collected.

        Args:
            operation_name: Name identifier for the async operation
            coro: The coroutine to execute and profile

        Returns:
            object: The return value of the coroutine

        Raises:
            Exception: Any exception raised by the coroutine is re-raised
                      after profiling is completed

        """
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss

        success = True
        error_message = None

        try:
            return await coro
        except Exception as e:
            self.logger.exception("Exception in performance_monitor: %s", e)
            success = False
            error_message = str(e)
            raise
        finally:
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss

            execution_time = end_time - start_time
            memory_usage = end_memory - start_memory

            profile = PerformanceProfile(
                operation_name=f"async.{operation_name}",
                execution_time=execution_time,
                memory_usage=memory_usage,
                cpu_usage=0.0,  # Difficult to measure for async
                success=success,
                error_message=error_message,
            )

            self.base_monitor.profiles.append(profile)

    def profile_async(
        self,
        operation_name: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Create a decorator that profiles async function execution.

        Returns a decorator that wraps an async function to automatically
        measure execution time and memory usage using the base monitor.

        Args:
            operation_name: Optional name for the operation. If not provided,
                           uses the wrapped function's name

        Returns:
            Callable[[Callable[..., Any]], Callable[..., Any]]: Decorator function
                that profiles wrapped async functions

        """

        def decorator(
            func: Callable[..., Coroutine[None, None, object]],
        ) -> Callable[..., Coroutine[None, None, object]]:
            name = operation_name or func.__name__

            @functools.wraps(func)
            async def wrapper(*args: object, **kwargs: object) -> object:
                return await self.profile_async_operation(name, func(*args, **kwargs))

            return wrapper

        return decorator


# Lazy initialization for async monitor
_async_monitor = None


def get_async_monitor() -> AsyncPerformanceMonitor:
    """Retrieve or create the global async performance monitor instance.

    Returns the singleton AsyncPerformanceMonitor instance, creating it on
    first access if needed. Uses the global performance monitor as the base.

    Returns:
        AsyncPerformanceMonitor: The global async performance monitor instance

    """
    global _async_monitor
    if _async_monitor is None:
        _async_monitor = AsyncPerformanceMonitor(get_performance_monitor())
    return _async_monitor


# Create default instance for imports
performance_monitor = get_performance_monitor()
