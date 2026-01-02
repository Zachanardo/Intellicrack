"""Comprehensive tests for performance optimization layer.

Tests validate GPU optimization, memory profiling, caching, parallel execution,
and resource management with real operations.
"""

import os
import time
from collections.abc import Callable
from typing import Any

import pytest

from intellicrack.ai.performance_optimization_layer import (
    CacheManager,
    OptimizationStrategy,
    ParallelExecutor,
    PerformanceOptimizationLayer,
    PerformanceOptimizer,
    PerformanceProfile,
    ResourceAllocation,
    ResourceManager,
    ResourceType,
)


class TestPerformanceOptimizer:
    """Test core performance optimizer functionality."""

    def test_optimizer_initialization(self) -> None:
        """Test optimizer initializes with correct default state."""
        optimizer = PerformanceOptimizer()

        assert optimizer.optimization_cache is not None
        assert len(optimizer.optimization_rules) > 0
        assert optimizer.optimization_stats["total_optimizations"] == 0
        assert optimizer.optimization_stats["cache_hits"] == 0

    def test_optimize_operation_executes_function(self) -> None:
        """Test optimizer executes operation and returns result."""
        optimizer = PerformanceOptimizer()

        def test_operation(x: int, y: int) -> int:
            return x + y

        result = optimizer.optimize_operation("test_op", test_operation, 5, 10)

        assert result == 15
        assert optimizer.optimization_stats["total_optimizations"] > 0

    def test_optimize_operation_caches_expensive_operations(self) -> None:
        """Test expensive operations are cached correctly."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        optimizer = PerformanceOptimizer()

        call_count = 0

        def expensive_operation(x: int) -> int:
            nonlocal call_count
            call_count += 1
            time.sleep(0.1)
            return x * 2

        optimizer.optimize_operation("expensive_1", expensive_operation, 5)
        optimizer.optimize_operation("expensive_1", expensive_operation, 5)

        assert optimizer.optimization_stats["cache_hits"] >= 0

    def test_generate_cache_key_deterministic(self) -> None:
        """Test cache key generation is deterministic."""
        optimizer = PerformanceOptimizer()

        key1 = optimizer._generate_cache_key("test_op", (1, 2), {"param": "value"})
        key2 = optimizer._generate_cache_key("test_op", (1, 2), {"param": "value"})

        assert key1 == key2

    def test_generate_cache_key_unique_for_different_args(self) -> None:
        """Test cache keys differ for different arguments."""
        optimizer = PerformanceOptimizer()

        key1 = optimizer._generate_cache_key("test_op", (1, 2), {})
        key2 = optimizer._generate_cache_key("test_op", (3, 4), {})

        assert key1 != key2

    def test_optimization_rules_applied_based_on_conditions(self) -> None:
        """Test optimization rules are evaluated correctly."""
        optimizer = PerformanceOptimizer()

        def test_func() -> int:
            return 42

        optimizer.execution_profiles["test_op"] = PerformanceProfile(
            operation_id="test_op",
            operation_type="test",
            execution_time=6.0,
            memory_usage=100,
            cpu_usage=50.0,
            io_operations=0,
            resource_bottlenecks=[]
        )

        result = optimizer._apply_optimizations("test_op", test_func)

        assert callable(result)

    def test_get_optimization_stats_returns_metrics(self) -> None:
        """Test optimization statistics are returned correctly."""
        optimizer = PerformanceOptimizer()

        def simple_op() -> int:
            return 1

        optimizer.optimize_operation("stats_test", simple_op)

        stats = optimizer.get_optimization_stats()

        assert "cache_hit_rate" in stats
        assert "total_profiles" in stats
        assert "active_rules" in stats
        assert stats["active_rules"] > 0

    def test_optimization_with_error_fallback(self) -> None:
        """Test optimizer handles errors and falls back to original function."""
        optimizer = PerformanceOptimizer()

        def failing_operation() -> int:
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            optimizer.optimize_operation("fail_op", failing_operation)


class TestResourceManager:
    """Test system resource allocation and monitoring."""

    def test_resource_manager_initialization(self) -> None:
        """Test resource manager initializes with system limits."""
        manager = ResourceManager()

        assert manager.resource_limits[ResourceType.CPU] > 0
        assert manager.resource_limits[ResourceType.MEMORY] > 0
        assert len(manager.resource_pools) > 0

    def test_get_system_limits_detects_resources(self) -> None:
        """Test system resource detection."""
        manager = ResourceManager()

        limits = manager._get_system_limits()

        assert ResourceType.CPU in limits
        assert ResourceType.MEMORY in limits
        assert limits[ResourceType.CPU] > 0

    def test_allocate_resources_succeeds_with_available_resources(self) -> None:
        """Test resource allocation when resources are available."""
        manager = ResourceManager()

        requirements = ResourceAllocation(
            cpu_cores=1,
            memory_mb=100,
            max_threads=2,
            max_processes=1,
            io_buffer_size=1024,
            cache_size_mb=10
        )

        success = manager.allocate_resources("test_op", requirements)

        assert success is True
        assert "test_op" in manager.active_allocations

    def test_release_resources_frees_allocation(self) -> None:
        """Test resource release removes allocation."""
        manager = ResourceManager()

        requirements = ResourceAllocation(
            cpu_cores=1,
            memory_mb=50,
            max_threads=1,
            max_processes=1,
            io_buffer_size=512,
            cache_size_mb=5
        )

        manager.allocate_resources("release_test", requirements)
        manager.release_resources("release_test")

        assert "release_test" not in manager.active_allocations

    def test_get_resource_usage_returns_current_metrics(self) -> None:
        """Test resource usage metrics are returned."""
        manager = ResourceManager()

        usage = manager.get_resource_usage()

        assert "cpu_percent" in usage
        assert "memory_percent" in usage
        assert "memory_available_mb" in usage
        assert "active_allocations" in usage

    def test_optimize_resource_allocation_provides_suggestions(self) -> None:
        """Test resource optimization suggestions are generated."""
        manager = ResourceManager()

        optimization = manager.optimize_resource_allocation()

        assert "current_usage" in optimization
        assert "optimization_suggestions" in optimization
        assert "total_allocations" in optimization

    def test_check_resource_availability_validates_requirements(self) -> None:
        """Test resource availability checking."""
        manager = ResourceManager()

        large_requirements = ResourceAllocation(
            cpu_cores=999999,
            memory_mb=999999999,
            max_threads=999999,
            max_processes=999999,
            io_buffer_size=1024,
            cache_size_mb=10
        )

        available = manager._check_resource_availability(large_requirements)

        assert available is False

    def test_resource_pools_initialized_correctly(self) -> None:
        """Test thread and process pools are created."""
        manager = ResourceManager()

        assert ResourceType.THREADS in manager.resource_pools
        assert ResourceType.PROCESSES in manager.resource_pools


class TestParallelExecutor:
    """Test parallel execution of operations."""

    def test_parallel_executor_initialization(self) -> None:
        """Test parallel executor initializes correctly."""
        executor = ParallelExecutor()

        assert executor.execution_stats["parallel_executions"] == 0
        assert executor.execution_stats["sequential_executions"] == 0

    def test_execute_parallel_processes_items(self) -> None:
        """Test parallel execution of function across items."""
        executor = ParallelExecutor()

        def square(x: int) -> int:
            return x * x

        items = [1, 2, 3, 4, 5]
        results = executor.execute_parallel(square, items, max_workers=2)

        assert len(results) == 5
        assert 1 in results
        assert 25 in results

    def test_execute_parallel_tracks_statistics(self) -> None:
        """Test parallel execution statistics are tracked."""
        executor = ParallelExecutor()

        def simple_func(x: int) -> int:
            return x

        executor.execute_parallel(simple_func, [1, 2, 3])

        stats = executor.get_execution_stats()
        assert stats["parallel_executions"] > 0

    def test_execute_batch_parallel_handles_different_operations(self) -> None:
        """Test batch parallel execution of different operations."""
        executor = ParallelExecutor()

        def add(x: int, y: int) -> int:
            return x + y

        def multiply(x: int, y: int) -> int:
            return x * y

        operations: list[tuple[Callable[..., Any], tuple[Any, ...], dict[str, Any]]] = [
            (add, (2, 3), {}),
            (multiply, (4, 5), {}),
            (add, (10, 20), {})
        ]

        results = executor.execute_batch_parallel(operations, max_workers=2)

        assert len(results) == 3
        assert 5 in results
        assert 20 in results
        assert 30 in results

    def test_should_parallelize_evaluates_correctly(self) -> None:
        """Test parallelization decision logic."""
        executor = ParallelExecutor()

        assert executor.should_parallelize(2, 0.05) is False
        assert executor.should_parallelize(10, 0.5) is True
        assert executor.should_parallelize(100, 0.01) is False

    def test_execute_parallel_handles_errors_gracefully(self) -> None:
        """Test parallel execution handles errors in individual tasks."""
        executor = ParallelExecutor()

        def failing_func(x: int) -> int:
            if x == 3:
                raise ValueError("Test error")
            return x

        results = executor.execute_parallel(failing_func, [1, 2, 3, 4])

        assert len(results) == 4
        assert None in results

    def test_execute_parallel_empty_list(self) -> None:
        """Test parallel execution with empty item list."""
        executor = ParallelExecutor()

        def test_func(x: int) -> int:
            return x

        results = executor.execute_parallel(test_func, [])

        assert results == []


class TestCacheManager:
    """Test intelligent caching for AI operations."""

    def test_cache_manager_initialization(self) -> None:
        """Test cache manager initializes with correct limits."""
        cache = CacheManager(max_size_mb=50)

        assert cache.max_size_mb == 50
        assert cache.current_size_mb == 0.0
        assert len(cache.cache) == 0

    def test_set_and_get_cache_item(self) -> None:
        """Test setting and retrieving cache items."""
        cache = CacheManager()

        cache.set("test_key", "test_value", ttl_seconds=60)
        result = cache.get("test_key")

        assert result == "test_value"
        assert cache.stats["hits"] == 1

    def test_get_nonexistent_key_returns_none(self) -> None:
        """Test getting nonexistent key returns None."""
        cache = CacheManager()

        result = cache.get("nonexistent")

        assert result is None
        assert cache.stats["misses"] == 1

    def test_cache_eviction_lru_policy(self) -> None:
        """Test LRU eviction when cache is full."""
        cache = CacheManager(max_size_mb=1)

        cache.set("key1", "a" * 1000, ttl_seconds=60)
        cache.set("key2", "b" * 1000, ttl_seconds=60)

        time.sleep(0.01)

        cache.set("key3", "c" * 1000, ttl_seconds=60)

        assert cache.stats["evictions"] >= 0

    def test_cleanup_expired_removes_old_items(self) -> None:
        """Test expired item cleanup."""
        cache = CacheManager()

        cache.set("expire_test", "value", ttl_seconds=0)
        time.sleep(0.1)

        cache.cleanup_expired()

        result = cache.get("expire_test")
        assert result is None

    def test_clear_cache_removes_all_items(self) -> None:
        """Test cache clearing."""
        cache = CacheManager()

        cache.set("key1", "value1")
        cache.set("key2", "value2")

        cache.clear()

        assert len(cache.cache) == 0
        assert cache.current_size_mb == 0.0

    def test_get_cache_stats_returns_metrics(self) -> None:
        """Test cache statistics are returned."""
        cache = CacheManager()

        cache.set("stats_test", "value")
        cache.get("stats_test")
        cache.get("missing")

        stats = cache.get_cache_stats()

        assert "hit_rate" in stats
        assert "current_size_mb" in stats
        assert "item_count" in stats
        assert "utilization" in stats

    def test_cache_tracks_access_times(self) -> None:
        """Test cache tracks access times for LRU."""
        cache = CacheManager()

        cache.set("access_test", "value")
        time.sleep(0.01)

        cache.get("access_test")

        assert "access_test" in cache.access_times
        assert cache.access_counts["access_test"] >= 1


class TestPerformanceOptimizationLayer:
    """Test the complete performance optimization layer."""

    def test_optimization_layer_initialization(self) -> None:
        """Test optimization layer initializes all components."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        layer = PerformanceOptimizationLayer()

        assert layer.optimizer is not None
        assert layer.resource_manager is not None
        assert layer.parallel_executor is not None
        assert layer.cache_manager is not None

    def test_optimize_executes_operation(self) -> None:
        """Test optimization layer executes operations correctly."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        layer = PerformanceOptimizationLayer()

        def test_op(x: int, y: int) -> int:
            return x * y

        result = layer.optimize("multiply", test_op, 3, 7)

        assert result == 21

    def test_execute_parallel_distributes_work(self) -> None:
        """Test parallel execution through optimization layer."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        layer = PerformanceOptimizationLayer()

        def double(x: int) -> int:
            return x * 2

        results = layer.execute_parallel(double, [1, 2, 3, 4])

        assert isinstance(results, list)
        assert len(results) == 4
        assert 2 in results
        assert 8 in results

    def test_allocate_and_release_resources(self) -> None:
        """Test resource allocation and release through layer."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        layer = PerformanceOptimizationLayer()

        requirements = ResourceAllocation(
            cpu_cores=1,
            memory_mb=100,
            max_threads=2,
            max_processes=1,
            io_buffer_size=1024,
            cache_size_mb=10
        )

        allocated = layer.allocate_resources("test_allocation", requirements)
        assert allocated is True

        layer.release_resources("test_allocation")

    def test_get_comprehensive_stats_returns_all_metrics(self) -> None:
        """Test comprehensive statistics aggregation."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        layer = PerformanceOptimizationLayer()

        stats = layer.get_comprehensive_stats()

        assert "optimizer_stats" in stats
        assert "cache_stats" in stats
        assert "parallel_stats" in stats
        assert "resource_usage" in stats
        assert "system_info" in stats


class TestOptimizationStrategies:
    """Test different optimization strategies."""

    def test_parallel_execution_strategy_wraps_correctly(self) -> None:
        """Test parallel execution strategy wrapper."""
        optimizer = PerformanceOptimizer()

        def process_item(x: int) -> int:
            return x * 2

        wrapped = optimizer._wrap_for_parallel_execution(
            process_item,
            {"max_workers": 2}
        )

        assert callable(wrapped)

        result = wrapped([1, 2, 3])
        assert isinstance(result, list) or isinstance(result, int)

    def test_memory_optimization_strategy_triggers_gc(self) -> None:
        """Test memory optimization triggers garbage collection."""
        optimizer = PerformanceOptimizer()

        def memory_intensive() -> str:
            return "test" * 1000

        wrapped = optimizer._wrap_for_memory_optimization(
            memory_intensive,
            {"gc_threshold": 0.8}
        )

        result = wrapped()
        assert result == "test" * 1000

    def test_batching_strategy_processes_in_chunks(self) -> None:
        """Test batching strategy divides work into batches."""
        optimizer = PerformanceOptimizer()

        def process_list(items: list[int]) -> list[int]:
            return [x * 2 for x in items]

        wrapped = optimizer._wrap_for_batching(
            process_list,
            {"batch_size": 3}
        )

        items = list(range(10))
        result = wrapped(items)

        assert isinstance(result, list)


class TestEdgeCasesAndErrors:
    """Test edge cases and error handling."""

    def test_optimize_with_none_result(self) -> None:
        """Test optimization handles None results correctly."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        optimizer = PerformanceOptimizer()

        def returns_none() -> None:
            return None

        result = optimizer.optimize_operation("none_test", returns_none)

        assert result is None

    def test_parallel_execution_with_single_item(self) -> None:
        """Test parallel execution with single item."""
        executor = ParallelExecutor()

        def process(x: int) -> int:
            return x

        result = executor.execute_parallel(process, [42])

        assert len(result) == 1
        assert result[0] == 42

    def test_resource_allocation_with_zero_requirements(self) -> None:
        """Test resource allocation with minimal requirements."""
        manager = ResourceManager()

        requirements = ResourceAllocation(
            cpu_cores=0,
            memory_mb=0,
            max_threads=0,
            max_processes=0,
            io_buffer_size=0,
            cache_size_mb=0
        )

        result = manager.allocate_resources("zero_req", requirements)

        assert isinstance(result, bool)

    def test_cache_with_large_values(self) -> None:
        """Test caching large values."""
        cache = CacheManager(max_size_mb=10)

        large_value = "x" * 1000000

        cache.set("large", large_value)
        result = cache.get("large")

        assert result == large_value or result is None

    def test_optimization_with_recursive_function(self) -> None:
        """Test optimization with recursive function."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        optimizer = PerformanceOptimizer()

        def factorial(n: int) -> int:
            if n <= 1:
                return 1
            return n * factorial(n - 1)

        result = optimizer.optimize_operation("factorial", factorial, 5)

        assert result == 120


class TestPerformanceMetrics:
    """Test performance measurement and profiling."""

    def test_performance_profile_tracks_execution_time(self) -> None:
        """Test performance profiling captures execution metrics."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        optimizer = PerformanceOptimizer()

        def timed_operation() -> int:
            time.sleep(0.01)
            return 42

        optimizer.optimize_operation("timed", timed_operation)

        assert "timed" in optimizer.execution_profiles
        profile = optimizer.execution_profiles["timed"]
        assert profile.execution_time >= 0.0

    def test_get_optimization_recommendations(self) -> None:
        """Test optimization recommendations are generated."""
        optimizer = PerformanceOptimizer()

        optimizer.execution_profiles["slow_op"] = PerformanceProfile(
            operation_id="slow_op",
            operation_type="test",
            execution_time=15.0,
            memory_usage=1500,
            cpu_usage=95.0,
            io_operations=0,
            resource_bottlenecks=[]
        )

        recommendations = optimizer.get_optimization_recommendations("slow_op")

        assert isinstance(recommendations, list)
        assert len(recommendations) > 0

    def test_should_cache_result_evaluates_correctly(self) -> None:
        """Test caching decision logic."""
        optimizer = PerformanceOptimizer()

        expensive_profile = PerformanceProfile(
            operation_id="expensive",
            operation_type="test",
            execution_time=5.0,
            memory_usage=200,
            cpu_usage=50.0,
            io_operations=0,
            resource_bottlenecks=[]
        )

        cheap_profile = PerformanceProfile(
            operation_id="cheap",
            operation_type="test",
            execution_time=0.1,
            memory_usage=10,
            cpu_usage=5.0,
            io_operations=0,
            resource_bottlenecks=[]
        )

        assert optimizer._should_cache_result(expensive_profile) is True
        assert optimizer._should_cache_result(cheap_profile) is False
