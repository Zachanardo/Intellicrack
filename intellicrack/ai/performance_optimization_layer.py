"""Performance Optimization Layer for AI Operations.

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

import concurrent.futures
import hashlib
import os
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, TypeVar

T = TypeVar("T")
ArgsType = TypeVar("ArgsType")
KwargsType = TypeVar("KwargsType")

from ..utils.logger import get_logger
from .learning_engine_simple import get_learning_engine
from .performance_monitor import profile_ai_operation

logger = get_logger(__name__)

try:
    from intellicrack.handlers.psutil_handler import psutil

    PSUTIL_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in performance_optimization_layer: %s", e)
    psutil = None
    PSUTIL_AVAILABLE = False


class OptimizationStrategy(Enum):
    """Types of optimization strategies."""

    CACHING = "caching"
    PARALLEL_EXECUTION = "parallel_execution"
    RESOURCE_POOLING = "resource_pooling"
    MEMORY_OPTIMIZATION = "memory_optimization"
    CPU_OPTIMIZATION = "cpu_optimization"
    IO_OPTIMIZATION = "io_optimization"
    ALGORITHM_SELECTION = "algorithm_selection"
    BATCHING = "batching"
    PRECOMPUTATION = "precomputation"
    LAZY_LOADING = "lazy_loading"


class ResourceType(Enum):
    """Types of system resources."""

    CPU = "cpu"
    MEMORY = "memory"
    DISK_IO = "disk_io"
    NETWORK_IO = "network_io"
    GPU = "gpu"
    THREADS = "threads"
    PROCESSES = "processes"


@dataclass
class PerformanceProfile:
    """Performance profile for optimization."""

    operation_id: str
    operation_type: str
    execution_time: float
    memory_usage: int
    cpu_usage: float
    io_operations: int
    resource_bottlenecks: list[ResourceType]
    optimization_suggestions: list[str] = field(default_factory=list)
    cache_hit_rate: float = 0.0
    parallelization_potential: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class OptimizationRule:
    """Rule for automatic optimization."""

    rule_id: str
    name: str
    condition: str
    strategy: OptimizationStrategy
    parameters: dict[str, Any]
    priority: int = 1
    enabled: bool = True
    success_rate: float = 0.0
    times_applied: int = 0
    avg_improvement: float = 0.0


@dataclass
class ResourceAllocation:
    """Resource allocation configuration."""

    cpu_cores: int
    memory_mb: int
    max_threads: int
    max_processes: int
    io_buffer_size: int
    cache_size_mb: int
    gpu_memory_mb: int = 0
    priority_level: str = "normal"


class PerformanceOptimizer:
    """Core performance optimizer for AI operations."""

    def __init__(self) -> None:
        """Initialize the performance optimizer.

        Sets up caching, execution profiling, optimization rules, and resource management
        for AI operation performance optimization.
        """
        self.optimization_cache: dict[str, Any] = {}
        self.execution_profiles: dict[str, PerformanceProfile] = {}
        self.optimization_rules: list[OptimizationRule] = []
        self.resource_manager = ResourceManager()
        self.parallel_executor = ParallelExecutor()
        self.cache_manager = CacheManager()

        # Performance tracking
        self.optimization_stats = {
            "total_optimizations": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "parallel_executions": 0,
            "memory_saved_mb": 0.0,
            "time_saved_seconds": 0.0,
        }

        # Initialize optimization rules
        self._initialize_optimization_rules()

        logger.info("Performance optimizer initialized")

    def _initialize_optimization_rules(self) -> None:
        """Initialize default optimization rules."""
        self.optimization_rules = [
            OptimizationRule(
                rule_id="cache_expensive_operations",
                name="Cache Expensive Operations",
                condition="execution_time > 5.0",
                strategy=OptimizationStrategy.CACHING,
                parameters={"ttl_seconds": 3600, "max_size": 1000},
                priority=1,
            ),
            OptimizationRule(
                rule_id="parallelize_batch_operations",
                name="Parallelize Batch Operations",
                condition="batch_size > 5 and cpu_usage < 0.7",
                strategy=OptimizationStrategy.PARALLEL_EXECUTION,
                parameters={"max_workers": 4, "chunk_size": 10},
                priority=2,
            ),
            OptimizationRule(
                rule_id="optimize_memory_usage",
                name="Optimize Memory Usage",
                condition="memory_usage > 500",  # MB
                strategy=OptimizationStrategy.MEMORY_OPTIMIZATION,
                parameters={"gc_threshold": 0.8, "chunk_processing": True},
                priority=1,
            ),
            OptimizationRule(
                rule_id="batch_io_operations",
                name="Batch I/O Operations",
                condition="io_operations > 20",
                strategy=OptimizationStrategy.BATCHING,
                parameters={"batch_size": 50, "flush_interval": 1.0},
                priority=2,
            ),
            OptimizationRule(
                rule_id="precompute_common_patterns",
                name="Precompute Common Patterns",
                condition="pattern_frequency > 0.8",
                strategy=OptimizationStrategy.PRECOMPUTATION,
                parameters={"pattern_cache_size": 200},
                priority=3,
            ),
        ]

    @profile_ai_operation("performance_optimization")
    def optimize_operation(self, operation_id: str, operation_func: Callable[..., T], *args: object, **kwargs: object) -> T:
        """Optimize execution of an AI operation.

        Applies applicable optimization strategies to the given operation based on profiling
        data and optimization rules. Caches results for expensive operations and records
        execution profiles for performance analysis.

        Args:
            operation_id: Unique identifier for the operation.
            operation_func: The callable to optimize and execute.
            *args: Positional arguments to pass to the operation function.
            **kwargs: Keyword arguments to pass to the operation function.

        Returns:
            The result of executing the optimized operation.

        """
        # Check if optimization is cached
        cache_key = self._generate_cache_key(operation_id, args, kwargs)

        cached_result = self.cache_manager.get(cache_key)
        if cached_result is not None:
            self.optimization_stats["cache_hits"] += 1
            logger.debug(f"Cache hit for operation {operation_id}")
            return cached_result

        self.optimization_stats["cache_misses"] += 1

        # Profile the operation
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss if PSUTIL_AVAILABLE else 0

        # Apply optimizations
        optimized_func = self._apply_optimizations(operation_id, operation_func)

        # Execute optimized operation
        try:
            result = optimized_func(*args, **kwargs)

            # Record performance profile
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss if PSUTIL_AVAILABLE else 0

            profile = PerformanceProfile(
                operation_id=operation_id,
                operation_type=operation_func.__name__,
                execution_time=end_time - start_time,
                memory_usage=(end_memory - start_memory) // (1024 * 1024),  # MB
                cpu_usage=psutil.cpu_percent() if PSUTIL_AVAILABLE else 0.0,
                io_operations=0,  # Would need more detailed tracking
                resource_bottlenecks=[],
            )

            self.execution_profiles[operation_id] = profile

            # Cache successful results
            if self._should_cache_result(profile):
                self.cache_manager.set(cache_key, result)

            # Record learning experience
            get_learning_engine().record_experience(
                task_type="performance_optimization",
                input_data={"operation_id": operation_id, "args_hash": cache_key},
                output_data={
                    "execution_time": profile.execution_time,
                    "memory_usage": profile.memory_usage,
                },
                success=True,
                confidence=0.8,
                execution_time=profile.execution_time,
                memory_usage=profile.memory_usage,
                context={"optimization_applied": True},
            )

            self.optimization_stats["total_optimizations"] += 1
            return result

        except Exception as e:
            logger.error(f"Error in optimized operation {operation_id}: {e}")
            # Fall back to original function
            return operation_func(*args, **kwargs)

    def _generate_cache_key(self, operation_id: str, args: tuple, kwargs: dict[str, Any]) -> str:
        """Generate deterministic cache key for operation.

        Creates a unique, reproducible hash key from the operation identifier and its arguments
        to enable consistent caching of operation results.

        Args:
            operation_id: Unique operation identifier.
            args: Positional arguments tuple.
            kwargs: Keyword arguments dictionary.

        Returns:
            MD5 hexadecimal hash string representing the operation and its arguments.

        """
        # Create deterministic hash from operation and arguments
        content = f"{operation_id}_{args!s}_{sorted(kwargs.items())!s}"
        return hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()

    def _apply_optimizations(self, operation_id: str, operation_func: Callable) -> Callable:
        """Apply applicable optimization strategies to operation.

        Iterates through enabled optimization rules and applies relevant strategies
        based on rule conditions and operation characteristics.

        Args:
            operation_id: Unique operation identifier.
            operation_func: The callable to apply optimizations to.

        Returns:
            The operation function wrapped with applicable optimizations.

        """
        optimized_func = operation_func

        # Check each optimization rule
        for rule in self.optimization_rules:
            if rule.enabled and self._rule_applies(rule, operation_id):
                optimized_func = self._apply_optimization_strategy(
                    optimized_func,
                    rule.strategy,
                    rule.parameters,
                )
                rule.times_applied += 1
                logger.debug(f"Applied optimization rule: {rule.name}")

        return optimized_func

    def _rule_applies(self, rule: OptimizationRule, operation_id: str) -> bool:
        """Determine if optimization rule applies to operation.

        Evaluates rule conditions against execution profiles to determine whether
        a specific optimization rule should be applied.

        Args:
            rule: The optimization rule to evaluate.
            operation_id: Unique operation identifier.

        Returns:
            True if the rule applies, False otherwise.

        """
        # Get recent profile for operation
        if operation_id in self.execution_profiles:
            profile = self.execution_profiles[operation_id]

            # Simple condition evaluation
            if "execution_time > 5.0" in rule.condition:
                return profile.execution_time > 5.0
            if "memory_usage > 500" in rule.condition:
                return profile.memory_usage > 500
            if "cpu_usage < 0.7" in rule.condition:
                return profile.cpu_usage < 0.7

        # Default to applying rule for new operations
        return True

    def _apply_optimization_strategy(self, func: Callable, strategy: OptimizationStrategy, parameters: dict[str, Any]) -> Callable:
        """Apply specific optimization strategy to function.

        Wraps the function with the appropriate optimization wrapper based on the
        selected strategy and strategy-specific parameters.

        Args:
            func: The callable to wrap with optimization.
            strategy: The optimization strategy to apply.
            parameters: Strategy-specific configuration parameters.

        Returns:
            The function wrapped with the specified optimization strategy.

        """
        if strategy == OptimizationStrategy.PARALLEL_EXECUTION:
            return self._wrap_for_parallel_execution(func, parameters)
        if strategy == OptimizationStrategy.MEMORY_OPTIMIZATION:
            return self._wrap_for_memory_optimization(func, parameters)
        if strategy == OptimizationStrategy.BATCHING:
            return self._wrap_for_batching(func, parameters)
        # Return original function if strategy not implemented
        return func

    def _wrap_for_parallel_execution(self, func: Callable, parameters: dict[str, Any]) -> Callable:
        """Wrap function for parallel execution.

        Creates a wrapper that distributes execution of iterable operations across
        multiple workers when applicable.

        Args:
            func: The callable to wrap for parallel execution.
            parameters: Strategy parameters including max_workers.

        Returns:
            A wrapped function that executes in parallel when possible.

        """
        max_workers = parameters.get("max_workers", 4)

        def parallel_wrapper(*args: object, **kwargs: object) -> object:
            """Execute function in parallel or sequentially based on arguments.

            Args:
                *args: Positional arguments for the wrapped function.
                **kwargs: Keyword arguments for the wrapped function.

            Returns:
                Function results from parallel or sequential execution.

            """
            # Check if arguments support parallel processing
            if len(args) > 0 and hasattr(args[0], "__iter__") and not isinstance(args[0], str):
                # Parallel processing for iterable first argument
                items = args[0]
                remaining_args = args[1:]

                results = self.parallel_executor.execute_parallel(
                    func,
                    items,
                    max_workers,
                    *remaining_args,
                    **kwargs,
                )
                return results
            # Regular execution for non-parallelizable arguments
            return func(*args, **kwargs)

        return parallel_wrapper

    def _wrap_for_memory_optimization(self, func: Callable, parameters: dict[str, Any]) -> Callable:
        """Wrap function for memory optimization.

        Creates a wrapper that monitors memory usage before and after execution,
        triggering garbage collection when memory usage exceeds threshold.

        Args:
            func: The callable to wrap for memory optimization.
            parameters: Strategy parameters including gc_threshold.

        Returns:
            A wrapped function that optimizes memory usage during execution.

        """
        gc_threshold = parameters.get("gc_threshold", 0.8)

        def memory_optimized_wrapper(*args: object, **kwargs: object) -> object:
            """Execute function with memory optimization and monitoring.

            Args:
                *args: Positional arguments for the wrapped function.
                **kwargs: Keyword arguments for the wrapped function.

            Returns:
                The result from the wrapped function execution.

            """
            import gc

            # Check memory usage before execution
            memory_percent = (
                psutil.virtual_memory()
                if PSUTIL_AVAILABLE
                else type(
                    "",
                    (),
                    {
                        "percent": 0,
                        "total": 8 * 1024 * 1024 * 1024,
                        "available": 4 * 1024 * 1024 * 1024,
                    },
                )().percent
                / 100.0
            )

            if memory_percent > gc_threshold:
                # Force garbage collection
                gc.collect()
                logger.debug("Triggered garbage collection for memory optimization")

            # Execute function
            result = func(*args, **kwargs)

            # Check memory after execution
            memory_percent_after = (
                psutil.virtual_memory()
                if PSUTIL_AVAILABLE
                else type(
                    "",
                    (),
                    {
                        "percent": 0,
                        "total": 8 * 1024 * 1024 * 1024,
                        "available": 4 * 1024 * 1024 * 1024,
                    },
                )().percent
                / 100.0
            )
            if memory_percent_after > gc_threshold:
                gc.collect()

            return result

        return memory_optimized_wrapper

    def _wrap_for_batching(self, func: Callable, parameters: dict[str, Any]) -> Callable:
        """Wrap function for batched execution.

        Creates a wrapper that divides list arguments into batches and processes
        them sequentially to improve memory efficiency and performance.

        Args:
            func: The callable to wrap for batched execution.
            parameters: Strategy parameters including batch_size.

        Returns:
            A wrapped function that batches list arguments during execution.

        """
        batch_size = parameters.get("batch_size", 50)

        def batched_wrapper(*args: object, **kwargs: object) -> object:
            """Execute function with automatic batching for list arguments.

            Args:
                *args: Positional arguments for the wrapped function.
                **kwargs: Keyword arguments for the wrapped function.

            Returns:
                Combined results from batched execution.

            """
            # Check if first argument is a list that can be batched
            if len(args) > 0 and isinstance(args[0], list) and len(args[0]) > batch_size:
                items = args[0]
                remaining_args = args[1:]

                results = []
                for i in range(0, len(items), batch_size):
                    batch = items[i : i + batch_size]
                    batch_result = func(batch, *remaining_args, **kwargs)
                    results.extend(batch_result if isinstance(batch_result, list) else [batch_result])

                return results
            return func(*args, **kwargs)

        return batched_wrapper

    def _should_cache_result(self, profile: PerformanceProfile) -> bool:
        """Determine if operation result should be cached.

        Makes caching decisions based on operation execution time and memory consumption.
        Expensive operations are cached to avoid redundant computation.

        Args:
            profile: Performance profile of the operation.

        Returns:
            True if the result should be cached, False otherwise.

        """
        # Cache expensive operations
        return profile.execution_time > 2.0 or profile.memory_usage > 100

    def get_optimization_recommendations(self, operation_id: str) -> list[str]:
        """Get optimization recommendations for operation.

        Analyzes execution profile and generates actionable recommendations for
        improving operation performance and resource efficiency.

        Args:
            operation_id: Unique operation identifier.

        Returns:
            List of optimization recommendations as strings.

        """
        recommendations = []

        if operation_id in self.execution_profiles:
            profile = self.execution_profiles[operation_id]

            if profile.execution_time > 10.0:
                recommendations.append("Consider parallel execution for long-running operations")

            if profile.memory_usage > 1000:  # 1GB
                recommendations.append("Implement memory optimization strategies")

            if profile.cpu_usage > 90:
                recommendations.append("Reduce CPU-intensive operations or use async processing")

            # Check cache hit rate
            if profile.cache_hit_rate < 0.3:
                recommendations.append("Improve caching strategy for better performance")

        return recommendations

    def get_optimization_stats(self) -> dict[str, Any]:
        """Get comprehensive optimization statistics.

        Collects and returns current optimization performance metrics including
        cache statistics, execution profiles, and active optimization rules.

        Returns:
            Dictionary containing optimization statistics and metrics.

        """
        return {
            **self.optimization_stats,
            "cache_hit_rate": self.optimization_stats["cache_hits"]
            / max(1, self.optimization_stats["cache_hits"] + self.optimization_stats["cache_misses"]),
            "total_profiles": len(self.execution_profiles),
            "active_rules": len([r for r in self.optimization_rules if r.enabled]),
        }


class ResourceManager:
    """Manages system resource allocation and monitoring."""

    def __init__(self) -> None:
        """Initialize the resource manager.

        Sets up resource pools, allocation tracking, system limits detection,
        and initializes resource management for optimal system utilization.
        """
        self.resource_pools: dict[ResourceType, Any] = {}
        self.allocation_history: deque = deque(maxlen=1000)
        self.resource_limits = self._get_system_limits()
        self.active_allocations: dict[str, ResourceAllocation] = {}

        # Initialize resource pools
        self._initialize_resource_pools()

        logger.info("Resource manager initialized")

    def _get_system_limits(self) -> dict[ResourceType, int]:
        """Get system resource limits and capabilities.

        Detects available CPU cores, total memory, and other system resource
        constraints for resource allocation and monitoring purposes.

        Returns:
            Dictionary mapping ResourceType to available system limits.

        """
        try:
            cpu_count = psutil.cpu_count(logical=False) if PSUTIL_AVAILABLE else 4
            # Ensure cpu_count is an integer
            if not isinstance(cpu_count, int):
                cpu_count = 4
        except (AttributeError, TypeError):
            cpu_count = 4

        return {
            ResourceType.CPU: cpu_count,
            # MB
            ResourceType.MEMORY: psutil.virtual_memory()
            if PSUTIL_AVAILABLE
            else type(
                "",
                (),
                {
                    "percent": 0,
                    "total": 8 * 1024 * 1024 * 1024,
                    "available": 4 * 1024 * 1024 * 1024,
                },
            )().total
            // (1024 * 1024),
            ResourceType.THREADS: 500,  # Reasonable default
            ResourceType.PROCESSES: 100,
            ResourceType.DISK_IO: 1000,  # MB/s estimate
            ResourceType.NETWORK_IO: 100,  # MB/s estimate
        }

    def _initialize_resource_pools(self) -> None:
        """Initialize thread and process executor pools.

        Creates thread pool and process pool executors based on system capabilities
        and resource limits for managing parallel and concurrent operations.
        """
        # Thread pool
        max_threads = min(32, self.resource_limits[ResourceType.CPU] * 4)
        self.resource_pools[ResourceType.THREADS] = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_threads,
        )

        # Process pool
        max_processes = min(self.resource_limits[ResourceType.CPU], 8)
        self.resource_pools[ResourceType.PROCESSES] = concurrent.futures.ProcessPoolExecutor(
            max_workers=max_processes,
        )

        logger.info(f"Initialized resource pools: {max_threads} threads, {max_processes} processes")

    @profile_ai_operation("resource_allocation")
    def allocate_resources(self, operation_id: str, requirements: ResourceAllocation) -> bool:
        """Allocate system resources for operation execution.

        Reserves CPU cores, memory, threads, and other resources needed for an operation.
        Checks resource availability before allocation and records allocation history.

        Args:
            operation_id: Unique operation identifier.
            requirements: ResourceAllocation configuration specifying needed resources.

        Returns:
            True if resources were successfully allocated, False if insufficient.

        """
        # Check if resources are available
        if not self._check_resource_availability(requirements):
            logger.warning(f"Insufficient resources for operation {operation_id}")
            return False

        # Reserve resources
        self.active_allocations[operation_id] = requirements

        # Record allocation
        self.allocation_history.append(
            {
                "operation_id": operation_id,
                "allocation": requirements,
                "timestamp": datetime.now(),
                "action": "allocate",
            },
        )

        logger.debug(f"Allocated resources for operation {operation_id}")
        return True

    def release_resources(self, operation_id: str) -> None:
        """Release previously allocated resources for operation.

        Frees system resources that were reserved for an operation, making them
        available for other operations. Records resource release in history.

        Args:
            operation_id: Unique operation identifier.

        """
        if operation_id in self.active_allocations:
            allocation = self.active_allocations[operation_id]
            del self.active_allocations[operation_id]

            # Record release
            self.allocation_history.append(
                {
                    "operation_id": operation_id,
                    "allocation": allocation,
                    "timestamp": datetime.now(),
                    "action": "release",
                },
            )

            logger.debug(f"Released resources for operation {operation_id}")

    def _check_resource_availability(self, requirements: ResourceAllocation) -> bool:
        """Check if required resources are currently available.

        Validates that sufficient CPU, memory, and thread pool capacity exist
        to meet the operation's resource requirements.

        Args:
            requirements: ResourceAllocation specifying required resources.

        Returns:
            True if all required resources are available, False otherwise.

        """
        # Check CPU cores
        if requirements.cpu_cores > self.resource_limits[ResourceType.CPU]:
            return False

        # Check memory
        available_memory = (
            psutil.virtual_memory()
            if PSUTIL_AVAILABLE
            else type(
                "",
                (),
                {
                    "percent": 0,
                    "total": 8 * 1024 * 1024 * 1024,
                    "available": 4 * 1024 * 1024 * 1024,
                },
            )().available
            // (1024 * 1024)
        )
        if requirements.memory_mb > available_memory:
            return False

        # Check thread pool capacity
        thread_pool = self.resource_pools[ResourceType.THREADS]
        return not (hasattr(thread_pool, "_threads") and len(thread_pool._threads) >= thread_pool._max_workers)

    def get_resource_usage(self) -> dict[str, float]:
        """Get current system resource usage metrics.

        Measures CPU percentage, memory usage, available memory, and disk I/O
        to monitor system resource consumption and availability.

        Returns:
            Dictionary containing current resource usage percentages and values.

        """
        cpu_usage = psutil.cpu_percent() if PSUTIL_AVAILABLE else 0.0
        memory = (
            psutil.virtual_memory()
            if PSUTIL_AVAILABLE
            else type(
                "",
                (),
                {
                    "percent": 0,
                    "total": 8 * 1024 * 1024 * 1024,
                    "available": 4 * 1024 * 1024 * 1024,
                },
            )()
        )
        disk_io = psutil.disk_io_counters() if PSUTIL_AVAILABLE else type("", (), {"read_bytes": 0, "write_bytes": 0})()

        usage = {
            "cpu_percent": cpu_usage,
            "memory_percent": memory.percent,
            "memory_available_mb": memory.available // (1024 * 1024),
            "active_allocations": len(self.active_allocations),
        }

        if disk_io:
            usage.update(
                {
                    "disk_read_mb": disk_io.read_bytes // (1024 * 1024),
                    "disk_write_mb": disk_io.write_bytes // (1024 * 1024),
                },
            )

        return usage

    def optimize_resource_allocation(self) -> dict[str, Any]:
        """Optimize current resource allocations.

        Analyzes resource usage patterns and generates optimization suggestions
        to improve overall system performance and resource efficiency.

        Returns:
            Dictionary containing current usage, optimization suggestions, and allocation totals.

        """
        optimizations = []

        # Analyze resource usage patterns
        current_usage = self.get_resource_usage()

        if current_usage["cpu_percent"] > 80:
            optimizations.append("High CPU usage - consider process parallelization")

        if current_usage["memory_percent"] > 85:
            optimizations.append("High memory usage - implement memory optimization")

        if len(self.active_allocations) > 20:
            optimizations.append("Many active allocations - consider resource pooling")

        return {
            "current_usage": current_usage,
            "optimization_suggestions": optimizations,
            "total_allocations": len(self.active_allocations),
        }


class ParallelExecutor:
    """Manages parallel execution of AI operations."""

    def __init__(self) -> None:
        """Initialize the parallel executor for AI operations.

        Sets up execution statistics tracking for monitoring parallel vs sequential
        execution performance and calculating speedup metrics.
        """
        self.execution_stats = {
            "parallel_executions": 0,
            "sequential_executions": 0,
            "average_speedup": 0.0,
            "total_time_saved": 0.0,
        }

        logger.info("Parallel executor initialized")

    @profile_ai_operation("parallel_execution")
    def execute_parallel(self, func: Callable, items: list[Any], max_workers: int | None = None, *args: object, **kwargs: object) -> list[Any]:
        """Execute function in parallel for list of items.

        Distributes function execution across multiple worker threads for each item
        in the input list. Measures baseline sequential performance and calculates
        parallel speedup metrics.

        Args:
            func: The callable to execute in parallel for each item.
            items: List of items to process.
            max_workers: Maximum number of worker threads (auto-detected if None).
            *args: Additional positional arguments to pass to the function.
            **kwargs: Additional keyword arguments to pass to the function.

        Returns:
            List of results from parallel execution of the function.

        """
        if not items:
            return []

        # Determine optimal number of workers
        if max_workers is None:
            max_workers = min(len(items), psutil.cpu_count(logical=False) if PSUTIL_AVAILABLE else 4)

        # Measure sequential baseline (for first few items)
        baseline_items = items[: min(3, len(items))]
        start_time = time.time()

        for item in baseline_items:
            func(item, *args, **kwargs)

        sequential_time_per_item = (time.time() - start_time) / len(baseline_items)
        estimated_sequential_time = sequential_time_per_item * len(items)

        # Execute in parallel
        start_parallel = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_item = {executor.submit(func, item, *args, **kwargs): item for item in items}

            # Collect results
            results = []
            for future in concurrent.futures.as_completed(future_to_item):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error in parallel execution: {e}")
                    results.append(None)

        parallel_time = time.time() - start_parallel

        # Calculate performance improvement
        speedup = estimated_sequential_time / parallel_time if parallel_time > 0 else 1.0
        time_saved = estimated_sequential_time - parallel_time

        # Update statistics
        self.execution_stats["parallel_executions"] += 1
        self.execution_stats["total_time_saved"] += time_saved
        self.execution_stats["average_speedup"] = (
            self.execution_stats["average_speedup"] * (self.execution_stats["parallel_executions"] - 1) + speedup
        ) / self.execution_stats["parallel_executions"]

        logger.info(f"Parallel execution: {speedup:.2f}x speedup, saved {time_saved:.2f}s")

        return results

    @profile_ai_operation("batch_parallel_execution")
    def execute_batch_parallel(self, operations: list[tuple[Callable, tuple, dict]], max_workers: int | None = None) -> list[Any]:
        """Execute multiple different operations in parallel.

        Processes a list of different callables with their respective arguments
        across multiple worker threads to maximize concurrent execution.

        Args:
            operations: List of tuples containing (callable, args, kwargs).
            max_workers: Maximum number of worker threads (auto-detected if None).

        Returns:
            List of results from parallel execution of all operations.

        """
        if not operations:
            return []

        if max_workers is None:
            max_workers = min(len(operations), psutil.cpu_count(logical=False) if PSUTIL_AVAILABLE else 4)

        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all operations
            future_to_operation = {executor.submit(func, *args, **kwargs): (func, args, kwargs) for func, args, kwargs in operations}

            # Collect results in order
            for future in concurrent.futures.as_completed(future_to_operation):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error in batch parallel execution: {e}")
                    results.append(None)

        self.execution_stats["parallel_executions"] += 1

        return results

    def should_parallelize(self, item_count: int, estimated_time_per_item: float) -> bool:
        """Determine if parallelization would be beneficial.

        Evaluates whether parallel execution would provide performance benefits
        based on item count and estimated execution time per item.

        Args:
            item_count: Number of items to process.
            estimated_time_per_item: Estimated execution time per item in seconds.

        Returns:
            True if parallelization would be beneficial, False otherwise.

        """
        # Don't parallelize small tasks
        if item_count < 3:
            return False

        # Don't parallelize very fast operations
        if estimated_time_per_item < 0.1:
            return False

        # Parallelize if total time > 2 seconds
        total_estimated_time = item_count * estimated_time_per_item
        return total_estimated_time > 2.0

    def get_execution_stats(self) -> dict[str, Any]:
        """Get parallel execution statistics.

        Retrieves current statistics for parallel execution performance including
        execution counts, speedup metrics, and time savings.

        Returns:
            Dictionary containing parallel execution statistics.

        """
        return self.execution_stats.copy()


class CacheManager:
    """Manages intelligent caching for AI operations."""

    def __init__(self, max_size_mb: int = 100) -> None:
        """Initialize the cache manager for AI operations.

        Args:
            max_size_mb: Maximum cache size in megabytes.

        """
        self.cache: dict[str, dict[str, Any]] = {}
        self.access_times: dict[str, datetime] = {}
        self.access_counts: dict[str, int] = defaultdict(int)
        self.max_size_mb = max_size_mb
        self.current_size_mb = 0.0

        # Cache statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_size_mb": 0.0,
        }

        logger.info(f"Cache manager initialized with {max_size_mb}MB limit")

    def get(self, key: str) -> object | None:
        """Retrieve value from cache if present.

        Looks up a cached value by key and updates access statistics for
        cache hit rate tracking and LRU eviction decisions.

        Args:
            key: Cache key for the value to retrieve.

        Returns:
            Cached value if key exists, None otherwise.

        """
        if key in self.cache:
            # Update access statistics
            self.access_times[key] = datetime.now()
            self.access_counts[key] += 1
            self.stats["hits"] += 1

            return self.cache[key]["value"]

        self.stats["misses"] += 1
        return None

    def set(self, key: str, value: object, ttl_seconds: int = 3600) -> None:
        """Store value in cache with TTL expiration.

        Caches a value with optional time-to-live. Automatically evicts least-recently-used
        items if cache exceeds size limits, and tracks item expiration for cleanup.

        Args:
            key: Cache key to store value under.
            value: Value to cache.
            ttl_seconds: Time-to-live for cache entry in seconds (default: 3600).

        """
        # Estimate size of cached item
        import sys

        item_size_mb = sys.getsizeof(value) / (1024 * 1024)

        # Check if we need to evict items
        while self.current_size_mb + item_size_mb > self.max_size_mb and self.cache:
            self._evict_lru_item()

        # Store the item
        expiry_time = datetime.now() + timedelta(seconds=ttl_seconds)
        self.cache[key] = {
            "value": value,
            "expiry": expiry_time,
            "size_mb": item_size_mb,
        }

        self.access_times[key] = datetime.now()
        self.access_counts[key] = 1
        self.current_size_mb += item_size_mb
        self.stats["total_size_mb"] = self.current_size_mb

        logger.debug(f"Cached item {key[:8]}... ({item_size_mb:.2f}MB)")

    def _evict_lru_item(self) -> None:
        """Evict least recently used cache item.

        Removes the cache item with the oldest access time to make room for new items
        when cache size limit is exceeded.
        """
        if not self.access_times:
            return

        # Find least recently used item
        lru_key = min(self.access_times.items(), key=lambda x: x[1])[0]

        # Remove from cache
        if lru_key in self.cache:
            item_size = self.cache[lru_key]["size_mb"]
            del self.cache[lru_key]
            del self.access_times[lru_key]
            del self.access_counts[lru_key]

            self.current_size_mb -= item_size
            self.stats["evictions"] += 1

            logger.debug(f"Evicted LRU item {lru_key[:8]}... ({item_size:.2f}MB)")

    def cleanup_expired(self) -> None:
        """Remove expired items from cache.

        Scans cache for items that have exceeded their TTL and removes them
        to free cache space and keep cache fresh.
        """
        now = datetime.now()
        expired_keys = []

        for key, item in self.cache.items():
            if item["expiry"] < now:
                expired_keys.append(key)

        for key in expired_keys:
            self._remove_item(key)

        if expired_keys:
            logger.debug(f"Removed {len(expired_keys)} expired cache items")

    def _remove_item(self, key: str) -> None:
        """Remove specific item from cache.

        Deletes a cache item and updates size tracking and access statistics.

        Args:
            key: Cache key to remove.

        """
        if key in self.cache:
            item_size = self.cache[key]["size_mb"]
            del self.cache[key]

            if key in self.access_times:
                del self.access_times[key]
            if key in self.access_counts:
                del self.access_counts[key]

            self.current_size_mb -= item_size

    def clear(self) -> None:
        """Clear entire cache.

        Removes all cached items and resets size tracking and statistics.
        """
        self.cache.clear()
        self.access_times.clear()
        self.access_counts.clear()
        self.current_size_mb = 0.0
        logger.info("Cache cleared")

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics and metrics.

        Returns comprehensive cache statistics including hit rate, size utilization,
        item count, and eviction metrics.

        Returns:
            Dictionary containing cache statistics and performance metrics.

        """
        hit_rate = self.stats["hits"] / max(1, self.stats["hits"] + self.stats["misses"])

        return {
            **self.stats,
            "hit_rate": hit_rate,
            "current_size_mb": self.current_size_mb,
            "max_size_mb": self.max_size_mb,
            "item_count": len(self.cache),
            "utilization": self.current_size_mb / self.max_size_mb,
        }


class PerformanceOptimizationLayer:
    """Run performance optimization layer."""

    def __init__(self) -> None:
        """Initialize the performance optimization layer.

        Sets up the optimizer, resource manager, parallel executor, and cache manager
        components, then starts background optimization processes.
        """
        self.optimizer = PerformanceOptimizer()
        self.resource_manager = ResourceManager()
        self.parallel_executor = ParallelExecutor()
        self.cache_manager = CacheManager()

        # Background optimization
        self._start_background_optimization()

        logger.info("Performance optimization layer initialized")

    def _start_background_optimization(self) -> None:
        """Start background optimization tasks.

        Launches a daemon thread that periodically cleans up expired cache items
        and optimizes resource allocations. Skipped when in testing mode.
        """
        # Skip thread creation during testing
        if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
            logger.info("Skipping background optimization worker (testing mode)")
            return

        def background_worker() -> None:
            while True:
                try:
                    # Cleanup expired cache items
                    self.cache_manager.cleanup_expired()

                    # Optimize resource allocations
                    self.resource_manager.optimize_resource_allocation()

                    # Sleep for 5 minutes
                    time.sleep(300)

                except Exception as e:
                    logger.error(f"Error in background optimization: {e}")
                    time.sleep(60)  # Wait 1 minute on error

        thread = threading.Thread(target=background_worker, daemon=True)
        thread.start()
        logger.info("Started background optimization worker")

    def optimize(self, operation_id: str, operation_func: Callable, *args: object, **kwargs: object) -> object:
        """Optimize operation execution as main entry point.

        Routes optimization request to the internal optimizer for applying
        performance optimization strategies and caching.

        Args:
            operation_id: Unique operation identifier.
            operation_func: The callable to optimize and execute.
            *args: Positional arguments for the operation function.
            **kwargs: Keyword arguments for the operation function.

        Returns:
            Result from optimized operation execution.

        """
        return self.optimizer.optimize_operation(operation_id, operation_func, *args, **kwargs)

    def execute_parallel(self, func: Callable, items: list[Any], max_workers: int | None = None) -> list[Any]:
        """Execute function in parallel for list of items.

        Distributes function execution across multiple worker threads.

        Args:
            func: Callable to execute in parallel.
            items: List of items to process.
            max_workers: Maximum worker threads (auto-detected if None).

        Returns:
            List of results from parallel execution.

        """
        return self.parallel_executor.execute_parallel(func, items, max_workers)

    def allocate_resources(self, operation_id: str, requirements: ResourceAllocation) -> bool:
        """Allocate resources for operation.

        Reserves system resources for the specified operation.

        Args:
            operation_id: Unique operation identifier.
            requirements: ResourceAllocation configuration.

        Returns:
            True if resources allocated successfully, False otherwise.

        """
        return self.resource_manager.allocate_resources(operation_id, requirements)

    def release_resources(self, operation_id: str) -> None:
        """Release resources for operation.

        Frees previously allocated resources for the specified operation.

        Args:
            operation_id: Unique operation identifier.

        """
        self.resource_manager.release_resources(operation_id)

    def get_comprehensive_stats(self) -> dict[str, Any]:
        """Get comprehensive optimization statistics.

        Collects and returns aggregate statistics from optimizer, cache manager,
        parallel executor, and resource manager along with system information.

        Returns:
            Dictionary containing comprehensive system and optimization statistics.

        """
        return {
            "optimizer_stats": self.optimizer.get_optimization_stats(),
            "cache_stats": self.cache_manager.get_cache_stats(),
            "parallel_stats": self.parallel_executor.get_execution_stats(),
            "resource_usage": self.resource_manager.get_resource_usage(),
            "system_info": {
                "cpu_count": psutil.cpu_count(logical=False) if PSUTIL_AVAILABLE else 4,
                "memory_total_gb": psutil.virtual_memory()
                if PSUTIL_AVAILABLE
                else type(
                    "",
                    (),
                    {
                        "percent": 0,
                        "total": 8 * 1024 * 1024 * 1024,
                        "available": 4 * 1024 * 1024 * 1024,
                    },
                )().total
                / (1024**3),
                "memory_available_gb": psutil.virtual_memory()
                if PSUTIL_AVAILABLE
                else type(
                    "",
                    (),
                    {
                        "percent": 0,
                        "total": 8 * 1024 * 1024 * 1024,
                        "available": 4 * 1024 * 1024 * 1024,
                    },
                )().available
                / (1024**3),
            },
        }


# Global performance optimization layer instance
performance_optimization_layer = PerformanceOptimizationLayer()
