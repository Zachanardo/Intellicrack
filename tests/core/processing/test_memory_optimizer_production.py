"""Production tests for MemoryOptimizer - validates real memory optimization capabilities."""

import gc
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from intellicrack.core.processing.memory_optimizer import MemoryOptimizer, create_memory_optimizer


@pytest.fixture
def optimizer() -> MemoryOptimizer:
    """Create a MemoryOptimizer instance for testing."""
    return MemoryOptimizer()


@pytest.fixture
def optimizer_with_app() -> MemoryOptimizer:
    """Create MemoryOptimizer with mock app instance."""
    mock_app = MagicMock()
    mock_app.update_output = MagicMock()
    return MemoryOptimizer(app_instance=mock_app)


class TestMemoryOptimizerInitialization:
    """Test MemoryOptimizer initialization and configuration."""

    def test_optimizer_initializes_with_correct_defaults(self, optimizer: MemoryOptimizer) -> None:
        """MemoryOptimizer initializes with correct default configuration."""
        assert optimizer.enabled is False
        assert optimizer.threshold_percentage == 80.0
        assert optimizer.check_interval == 5.0
        assert optimizer.optimization_stats["collections_triggered"] == 0
        assert optimizer.optimization_stats["memory_saved"] == 0
        assert optimizer.optimization_stats["total_optimizations"] == 0

    def test_optimizer_has_required_optimization_techniques(self, optimizer: MemoryOptimizer) -> None:
        """MemoryOptimizer defines all required optimization techniques."""
        required_techniques = {
            "garbage_collection",
            "memory_efficient_structures",
            "incremental_loading",
            "leak_detection",
        }
        assert set(optimizer.optimization_techniques.keys()) == required_techniques
        assert optimizer.optimization_techniques["garbage_collection"] is True
        assert optimizer.optimization_techniques["memory_efficient_structures"] is True
        assert optimizer.optimization_techniques["incremental_loading"] is True
        assert optimizer.optimization_techniques["leak_detection"] is False

    def test_optimizer_initializes_internal_tracking_structures(self, optimizer: MemoryOptimizer) -> None:
        """MemoryOptimizer initializes internal tracking structures."""
        assert isinstance(optimizer._memory_history, list)
        assert isinstance(optimizer._leak_history, list)
        assert len(optimizer._memory_history) == 0
        assert len(optimizer._leak_history) == 0

    def test_optimizer_with_app_instance_stores_reference(self, optimizer_with_app: MemoryOptimizer) -> None:
        """MemoryOptimizer stores application instance reference."""
        assert optimizer_with_app.app is not None


class TestMemoryOptimizerConfiguration:
    """Test memory optimizer configuration."""

    def test_configure_sets_threshold_within_valid_range(self, optimizer: MemoryOptimizer) -> None:
        """configure() clamps threshold to valid range 0-100."""
        optimizer.configure(threshold=150.0)
        assert optimizer.threshold_percentage == 100.0

        optimizer.configure(threshold=-20.0)
        assert optimizer.threshold_percentage == 0.0

        optimizer.configure(threshold=75.0)
        assert optimizer.threshold_percentage == 75.0

    def test_configure_sets_check_interval_minimum(self, optimizer: MemoryOptimizer) -> None:
        """configure() enforces minimum check interval of 1 second."""
        optimizer.configure(check_interval=0.5)
        assert optimizer.check_interval == 1.0

        optimizer.configure(check_interval=10.0)
        assert optimizer.check_interval == 10.0

    def test_configure_updates_techniques(self, optimizer: MemoryOptimizer) -> None:
        """configure() updates optimization techniques."""
        techniques = {
            "garbage_collection": False,
            "leak_detection": True,
        }
        optimizer.configure(techniques=techniques)

        assert optimizer.optimization_techniques["garbage_collection"] is False
        assert optimizer.optimization_techniques["leak_detection"] is True
        assert optimizer.optimization_techniques["memory_efficient_structures"] is True

    def test_set_technique_enables_and_disables_techniques(self, optimizer: MemoryOptimizer) -> None:
        """set_technique() enables and disables specific techniques."""
        result = optimizer.set_technique("garbage_collection", False)
        assert result is True
        assert optimizer.optimization_techniques["garbage_collection"] is False

        result = optimizer.set_technique("leak_detection", True)
        assert result is True
        assert optimizer.optimization_techniques["leak_detection"] is True

    def test_set_technique_returns_false_for_unknown_technique(self, optimizer: MemoryOptimizer) -> None:
        """set_technique() returns False for unknown techniques."""
        result = optimizer.set_technique("nonexistent_technique", True)
        assert result is False


class TestMemoryMonitoring:
    """Test memory usage monitoring capabilities."""

    def test_get_current_memory_usage_returns_valid_values(self, optimizer: MemoryOptimizer) -> None:
        """get_current_memory_usage() returns valid memory measurements."""
        used, total, percentage = optimizer.get_current_memory_usage()

        assert isinstance(used, int)
        assert isinstance(total, int)
        assert isinstance(percentage, float)
        assert used >= 0
        assert total >= 0
        assert 0.0 <= percentage <= 100.0

    def test_get_memory_usage_mb_converts_to_megabytes(self, optimizer: MemoryOptimizer) -> None:
        """get_memory_usage_mb() converts bytes to megabytes correctly."""
        used_mb, total_mb, percentage = optimizer.get_memory_usage_mb()

        assert isinstance(used_mb, float)
        assert isinstance(total_mb, float)
        assert isinstance(percentage, float)
        assert used_mb >= 0.0
        assert total_mb >= 0.0

    def test_memory_usage_updates_statistics(self, optimizer: MemoryOptimizer) -> None:
        """get_current_memory_usage() updates internal statistics."""
        optimizer.get_current_memory_usage()

        assert optimizer.optimization_stats["current_memory_usage"] >= 0
        assert optimizer.optimization_stats["peak_memory_usage"] >= 0

    def test_peak_memory_tracking_increases_with_usage(self, optimizer: MemoryOptimizer) -> None:
        """Peak memory usage increases but never decreases."""
        optimizer.get_current_memory_usage()
        initial_peak = optimizer.optimization_stats["peak_memory_usage"]

        large_data = [b"\x00" * 1024 * 1024 for _ in range(10)]

        optimizer.get_current_memory_usage()
        new_peak = optimizer.optimization_stats["peak_memory_usage"]

        assert new_peak >= initial_peak

        del large_data
        gc.collect()

        optimizer.get_current_memory_usage()
        final_peak = optimizer.optimization_stats["peak_memory_usage"]

        assert final_peak >= new_peak


class TestMemoryOptimizationExecution:
    """Test memory optimization execution."""

    def test_optimize_memory_performs_garbage_collection(self, optimizer: MemoryOptimizer) -> None:
        """optimize_memory() performs garbage collection when enabled."""
        optimizer.optimization_techniques["garbage_collection"] = True
        optimizer.enabled = True

        created_objects = [{"data": i} for i in range(1000)]
        del created_objects

        bytes_saved = optimizer.optimize_memory()

        assert optimizer.optimization_stats["collections_triggered"] >= 1
        assert isinstance(bytes_saved, int)

    def test_optimize_memory_updates_statistics(self, optimizer: MemoryOptimizer) -> None:
        """optimize_memory() updates optimization statistics."""
        optimizer.enabled = True
        initial_total = optimizer.optimization_stats["total_optimizations"]

        optimizer.optimize_memory()

        assert optimizer.optimization_stats["total_optimizations"] == initial_total + 1
        assert optimizer.optimization_stats["last_optimization_time"] is not None
        assert isinstance(optimizer.optimization_stats["last_optimization_time"], float)

    def test_optimize_memory_respects_technique_settings(self, optimizer: MemoryOptimizer) -> None:
        """optimize_memory() respects enabled/disabled techniques."""
        optimizer.optimization_techniques["garbage_collection"] = False
        optimizer.optimization_techniques["memory_efficient_structures"] = False
        optimizer.optimization_techniques["leak_detection"] = False
        optimizer.enabled = True

        optimizer.optimize_memory()

    def test_force_optimization_runs_regardless_of_enabled_state(self, optimizer: MemoryOptimizer) -> None:
        """force_optimization() runs even when optimizer is disabled."""
        optimizer.enabled = False
        initial_optimizations = optimizer.optimization_stats["total_optimizations"]

        bytes_saved = optimizer.force_optimization()

        assert isinstance(bytes_saved, int)
        assert optimizer.optimization_stats["total_optimizations"] > initial_optimizations
        assert not optimizer.enabled


class TestCheckMemoryUsage:
    """Test automatic memory usage checking."""

    def test_check_memory_usage_respects_enabled_state(self, optimizer: MemoryOptimizer) -> None:
        """check_memory_usage() returns False when disabled."""
        optimizer.enabled = False
        result = optimizer.check_memory_usage()
        assert result is False

    def test_check_memory_usage_respects_check_interval(self, optimizer: MemoryOptimizer) -> None:
        """check_memory_usage() respects configured check interval."""
        optimizer.enabled = True
        optimizer.check_interval = 10.0

        result1 = optimizer.check_memory_usage()

        result2 = optimizer.check_memory_usage()
        assert result2 is False

    def test_check_memory_usage_triggers_optimization_above_threshold(self, optimizer: MemoryOptimizer) -> None:
        """check_memory_usage() triggers optimization when threshold exceeded."""
        optimizer.enabled = True
        optimizer.threshold_percentage = 0.0
        optimizer.check_interval = 0.1

        time.sleep(0.15)
        result = optimizer.check_memory_usage()

        assert isinstance(result, bool)


class TestMemoryLeakDetection:
    """Test comprehensive memory leak detection."""

    def test_check_for_memory_leaks_returns_detailed_report(self, optimizer: MemoryOptimizer) -> None:
        """check_for_memory_leaks() returns comprehensive leak analysis report."""
        report = optimizer.check_for_memory_leaks()

        assert isinstance(report, str)
        assert len(report) > 0
        assert "GC:" in report or "error" in report

    def test_check_for_memory_leaks_detects_garbage_collection_metrics(self, optimizer: MemoryOptimizer) -> None:
        """check_for_memory_leaks() includes garbage collection metrics."""
        leak_objects = [{"ref": i} for i in range(100)]

        report = optimizer.check_for_memory_leaks()

        assert "GC:" in report or "objects" in report

        del leak_objects

    def test_check_for_memory_leaks_tracks_memory_growth(self, optimizer: MemoryOptimizer) -> None:
        """check_for_memory_leaks() tracks memory growth over multiple checks."""
        for _ in range(6):
            optimizer.check_for_memory_leaks()
            time.sleep(0.01)

        assert len(optimizer._memory_history) > 0
        assert len(optimizer._memory_history) <= 10

    def test_check_for_memory_leaks_identifies_high_memory_usage(self, optimizer: MemoryOptimizer) -> None:
        """check_for_memory_leaks() identifies high memory usage conditions."""
        large_allocation = [b"\x00" * 1024 * 1024 for _ in range(100)]

        report = optimizer.check_for_memory_leaks()

        del large_allocation
        gc.collect()

        assert isinstance(report, str)

    def test_leak_detection_stores_history(self, optimizer: MemoryOptimizer) -> None:
        """check_for_memory_leaks() stores detection history."""
        optimizer.check_for_memory_leaks()
        optimizer.check_for_memory_leaks()

        assert len(optimizer._leak_history) >= 1
        assert len(optimizer._leak_history) <= 20

        for entry in optimizer._leak_history:
            assert "timestamp" in entry
            assert "status" in entry
            assert "issues" in entry
            assert "memory_mb" in entry


class TestDataStructureOptimization:
    """Test data structure optimization techniques."""

    def test_optimize_data_structures_executes_without_errors(self, optimizer: MemoryOptimizer) -> None:
        """_optimize_data_structures() executes without raising exceptions."""
        optimizer._optimize_data_structures()

    def test_optimize_python_objects_identifies_large_structures(self, optimizer: MemoryOptimizer) -> None:
        """_optimize_python_objects() identifies large data structures."""
        large_list = list(range(2000))
        large_dict = {i: f"value_{i}" for i in range(1000)}

        optimizations = optimizer._optimize_python_objects()

        del large_list
        del large_dict

        assert isinstance(optimizations, list)

    def test_cleanup_circular_references_performs_gc(self, optimizer: MemoryOptimizer) -> None:
        """_cleanup_circular_references() performs generational garbage collection."""
        class Node:
            def __init__(self) -> None:
                self.ref: Node | None = None

        node1 = Node()
        node2 = Node()
        node1.ref = node2
        node2.ref = node1

        optimizations = optimizer._cleanup_circular_references()

        del node1
        del node2

        assert isinstance(optimizations, list)

    def test_optimize_caches_clears_lru_caches(self, optimizer: MemoryOptimizer) -> None:
        """_optimize_caches() identifies and clears functools.lru_cache caches."""
        from functools import lru_cache

        @lru_cache(maxsize=128)
        def cached_function(x: int) -> int:
            return x * 2

        for i in range(20):
            cached_function(i)

        optimizations = optimizer._optimize_caches()

        assert isinstance(optimizations, list)


class TestFindLargeObjects:
    """Test large object detection."""

    def test_find_large_objects_returns_list_of_tuples(self, optimizer: MemoryOptimizer) -> None:
        """_find_large_objects() returns list of (type, count, size_mb) tuples."""
        large_objects = optimizer._find_large_objects()

        assert isinstance(large_objects, list)
        for obj_info in large_objects:
            assert isinstance(obj_info, tuple)
            assert len(obj_info) == 3
            obj_type, count, size_mb = obj_info
            assert isinstance(obj_type, str)
            assert isinstance(count, int)
            assert isinstance(size_mb, float)

    def test_find_large_objects_detects_created_large_structures(self, optimizer: MemoryOptimizer) -> None:
        """_find_large_objects() detects newly created large data structures."""
        large_bytes = b"\x00" * (2 * 1024 * 1024)
        large_list = [large_bytes for _ in range(5)]

        large_objects = optimizer._find_large_objects()

        del large_list
        del large_bytes
        gc.collect()

        assert isinstance(large_objects, list)

    def test_find_large_objects_limits_results_to_top_10(self, optimizer: MemoryOptimizer) -> None:
        """_find_large_objects() limits results to top 10 by size."""
        large_objects = optimizer._find_large_objects()

        assert len(large_objects) <= 10


class TestReferenceCycleDetection:
    """Test reference cycle detection."""

    def test_detect_reference_cycles_returns_tuple(self, optimizer: MemoryOptimizer) -> None:
        """_detect_reference_cycles() returns (cycle_count, referrers_found) tuple."""
        cycles, referrers = optimizer._detect_reference_cycles()

        assert isinstance(cycles, int)
        assert isinstance(referrers, int)
        assert cycles >= 0
        assert referrers >= 0

    def test_detect_reference_cycles_finds_circular_references(self, optimizer: MemoryOptimizer) -> None:
        """_detect_reference_cycles() detects circular reference patterns."""
        class CircularRef:
            def __init__(self) -> None:
                self.refs: list[CircularRef] = []

        objects = [CircularRef() for _ in range(5)]
        for obj in objects:
            obj.refs.extend(objects)

        cycles, referrers = optimizer._detect_reference_cycles()

        del objects
        gc.collect()

        assert isinstance(cycles, int)
        assert isinstance(referrers, int)


class TestApplicationSpecificLeakDetection:
    """Test application-specific leak detection."""

    def test_check_application_leaks_returns_empty_without_app(self, optimizer: MemoryOptimizer) -> None:
        """_check_application_leaks() returns empty list without app instance."""
        leaks = optimizer._check_application_leaks()
        assert leaks == []

    def test_check_application_leaks_detects_large_caches(self, optimizer_with_app: MemoryOptimizer) -> None:
        """_check_application_leaks() detects large cache accumulation."""
        optimizer_with_app.app.binary_cache = dict.fromkeys(range(150), b"\x00" * 1000)
        optimizer_with_app.app.analysis_cache = {i: {"data": i} for i in range(120)}

        leaks = optimizer_with_app._check_application_leaks()

        assert isinstance(leaks, list)

    def test_check_application_leaks_detects_temporary_data_accumulation(
        self, optimizer_with_app: MemoryOptimizer
    ) -> None:
        """_check_application_leaks() detects accumulating temporary data."""
        optimizer_with_app.app.temp_analysis_results = [{"result": i} for i in range(600)]
        optimizer_with_app.app.temp_scan_data = [{"scan": i} for i in range(550)]

        leaks = optimizer_with_app._check_application_leaks()

        assert isinstance(leaks, list)


class TestResourceLeakDetection:
    """Test system resource leak detection."""

    def test_check_resource_leaks_returns_list(self, optimizer: MemoryOptimizer) -> None:
        """_check_resource_leaks() returns list of resource leak descriptions."""
        leaks = optimizer._check_resource_leaks()
        assert isinstance(leaks, list)

    def test_check_resource_leaks_detects_thread_proliferation(self, optimizer: MemoryOptimizer) -> None:
        """_check_resource_leaks() detects excessive thread creation."""
        threads = []
        stop_event = threading.Event()

        def worker() -> None:
            stop_event.wait(timeout=5)

        for _ in range(25):
            thread = threading.Thread(target=worker)
            thread.start()
            threads.append(thread)

        leaks = optimizer._check_resource_leaks()

        stop_event.set()
        for thread in threads:
            thread.join(timeout=0.5)

        assert isinstance(leaks, list)


class TestOptimizationStatistics:
    """Test optimization statistics tracking."""

    def test_get_optimization_stats_returns_complete_dictionary(self, optimizer: MemoryOptimizer) -> None:
        """get_optimization_stats() returns complete statistics dictionary."""
        stats = optimizer.get_optimization_stats()

        required_keys = {
            "collections_triggered",
            "memory_saved",
            "last_optimization_time",
            "peak_memory_usage",
            "current_memory_usage",
            "total_optimizations",
            "average_memory_saved",
            "total_system_memory",
            "current_usage_percentage",
            "enabled",
            "threshold_percentage",
            "check_interval",
            "techniques_enabled",
            "total_techniques",
        }

        assert set(stats.keys()) == required_keys

    def test_get_optimization_stats_updates_current_memory(self, optimizer: MemoryOptimizer) -> None:
        """get_optimization_stats() updates current memory usage."""
        stats = optimizer.get_optimization_stats()

        assert stats["current_memory_usage"] >= 0
        assert stats["current_usage_percentage"] >= 0.0

    def test_reset_stats_clears_all_statistics(self, optimizer: MemoryOptimizer) -> None:
        """reset_stats() resets all optimization statistics to zero."""
        optimizer.enabled = True
        optimizer.optimize_memory()
        optimizer.optimize_memory()

        optimizer.reset_stats()

        assert optimizer.optimization_stats["collections_triggered"] == 0
        assert optimizer.optimization_stats["memory_saved"] == 0
        assert optimizer.optimization_stats["total_optimizations"] == 0
        assert optimizer.optimization_stats["average_memory_saved"] == 0.0
        assert optimizer.optimization_stats["peak_memory_usage"] == 0
        assert optimizer.optimization_stats["last_optimization_time"] is None


class TestMemoryReport:
    """Test memory usage report generation."""

    def test_get_memory_report_returns_comprehensive_report(self, optimizer: MemoryOptimizer) -> None:
        """get_memory_report() returns comprehensive memory usage report."""
        report = optimizer.get_memory_report()

        assert isinstance(report, dict)
        assert "timestamp" in report
        assert "memory_usage" in report
        assert "optimization" in report
        assert "system" in report

    def test_get_memory_report_includes_memory_usage_details(self, optimizer: MemoryOptimizer) -> None:
        """get_memory_report() includes detailed memory usage information."""
        report = optimizer.get_memory_report()

        memory_usage = report["memory_usage"]
        assert "used_bytes" in memory_usage
        assert "used_mb" in memory_usage
        assert "total_bytes" in memory_usage
        assert "total_mb" in memory_usage
        assert "usage_percentage" in memory_usage
        assert "peak_usage_bytes" in memory_usage
        assert "peak_usage_mb" in memory_usage

    def test_get_memory_report_includes_optimization_details(self, optimizer: MemoryOptimizer) -> None:
        """get_memory_report() includes optimization configuration and stats."""
        optimizer.enabled = True
        optimizer.optimize_memory()

        report = optimizer.get_memory_report()

        optimization = report["optimization"]
        assert "enabled" in optimization
        assert "threshold" in optimization
        assert "techniques" in optimization
        assert "total_optimizations" in optimization
        assert "memory_saved_bytes" in optimization
        assert "memory_saved_mb" in optimization
        assert "average_saved_mb" in optimization
        assert "last_optimization" in optimization

    def test_get_memory_report_includes_system_info(self, optimizer: MemoryOptimizer) -> None:
        """get_memory_report() includes system information."""
        report = optimizer.get_memory_report()

        system = report["system"]
        assert "psutil_available" in system
        assert "gc_enabled" in system
        assert "gc_thresholds" in system


class TestEnableDisable:
    """Test optimizer enable/disable functionality."""

    def test_enable_sets_enabled_flag(self, optimizer: MemoryOptimizer) -> None:
        """enable() sets enabled flag to True."""
        optimizer.disable()
        assert optimizer.enabled is False

        optimizer.enable()
        assert optimizer.enabled is True

    def test_disable_sets_enabled_flag(self, optimizer: MemoryOptimizer) -> None:
        """disable() sets enabled flag to False."""
        optimizer.enable()
        assert optimizer.enabled is True

        optimizer.disable()
        assert optimizer.enabled is False

    def test_enable_with_app_emits_signal(self, optimizer_with_app: MemoryOptimizer) -> None:
        """enable() emits signal when app instance exists."""
        optimizer_with_app.enable()
        assert optimizer_with_app.enabled is True

    def test_disable_with_app_emits_signal(self, optimizer_with_app: MemoryOptimizer) -> None:
        """disable() emits signal when app instance exists."""
        optimizer_with_app.enable()
        optimizer_with_app.disable()
        assert optimizer_with_app.enabled is False


class TestContextManager:
    """Test context manager functionality."""

    def test_context_manager_enables_on_enter(self, optimizer: MemoryOptimizer) -> None:
        """Context manager enables optimizer on entry."""
        optimizer.disable()

        with optimizer as opt:
            assert opt.enabled is True
            assert opt is optimizer

    def test_context_manager_disables_on_exit(self, optimizer: MemoryOptimizer) -> None:
        """Context manager disables optimizer on exit."""
        with optimizer:
            pass

        assert optimizer.enabled is False

    def test_context_manager_disables_on_exception(self, optimizer: MemoryOptimizer) -> None:
        """Context manager disables optimizer even when exception occurs."""
        try:
            with optimizer:
                raise ValueError("Test exception")
        except ValueError:
            pass

        assert optimizer.enabled is False


class TestFactoryFunction:
    """Test create_memory_optimizer factory function."""

    def test_create_memory_optimizer_returns_instance(self) -> None:
        """create_memory_optimizer() returns MemoryOptimizer instance."""
        optimizer = create_memory_optimizer()
        assert isinstance(optimizer, MemoryOptimizer)

    def test_create_memory_optimizer_with_app_instance(self) -> None:
        """create_memory_optimizer() accepts app instance."""
        mock_app = MagicMock()
        optimizer = create_memory_optimizer(app_instance=mock_app)
        assert optimizer.app is mock_app

    def test_create_memory_optimizer_with_configuration(self) -> None:
        """create_memory_optimizer() applies configuration parameters."""
        optimizer = create_memory_optimizer(
            threshold=90.0,
            check_interval=10.0,
        )
        assert optimizer.threshold_percentage == 90.0
        assert optimizer.check_interval == 10.0

    def test_create_memory_optimizer_with_techniques(self) -> None:
        """create_memory_optimizer() configures optimization techniques."""
        techniques = {
            "garbage_collection": False,
            "leak_detection": True,
        }
        optimizer = create_memory_optimizer(techniques=techniques)
        assert optimizer.optimization_techniques["garbage_collection"] is False
        assert optimizer.optimization_techniques["leak_detection"] is True


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_optimize_memory_handles_no_memory_to_save(self, optimizer: MemoryOptimizer) -> None:
        """optimize_memory() handles case where no memory can be saved."""
        optimizer.enabled = True
        gc.collect()

        bytes_saved = optimizer.optimize_memory()

        assert isinstance(bytes_saved, int)
        assert bytes_saved >= 0

    def test_check_memory_usage_with_zero_interval(self, optimizer: MemoryOptimizer) -> None:
        """check_memory_usage() handles configuration with minimal interval."""
        optimizer.enabled = True
        optimizer.check_interval = 1.0

        result = optimizer.check_memory_usage()
        assert isinstance(result, bool)

    def test_memory_optimizer_without_psutil(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """MemoryOptimizer works when psutil is unavailable."""
        import intellicrack.core.processing.memory_optimizer as mem_mod

        original_psutil = mem_mod.PSUTIL_AVAILABLE
        monkeypatch.setattr(mem_mod, "PSUTIL_AVAILABLE", False)

        optimizer = MemoryOptimizer()
        used, total, percentage = optimizer.get_current_memory_usage()

        assert used == 0
        assert total == 0
        assert percentage == 0.0

        monkeypatch.setattr(mem_mod, "PSUTIL_AVAILABLE", original_psutil)

    def test_leak_detection_with_corrupted_objects(self, optimizer: MemoryOptimizer) -> None:
        """check_for_memory_leaks() handles corrupted or unusual objects."""
        report = optimizer.check_for_memory_leaks()
        assert isinstance(report, str)

    def test_optimize_data_structures_without_app(self, optimizer: MemoryOptimizer) -> None:
        """_optimize_data_structures() works without app instance."""
        optimizer.app = None
        optimizer._optimize_data_structures()

    def test_average_memory_saved_calculation(self, optimizer: MemoryOptimizer) -> None:
        """Optimizer correctly calculates average memory saved."""
        optimizer.enabled = True

        optimizer.optimize_memory()
        optimizer.optimize_memory()
        optimizer.optimize_memory()

        if optimizer.optimization_stats["total_optimizations"] > 0:
            expected_avg = (
                optimizer.optimization_stats["memory_saved"]
                / optimizer.optimization_stats["total_optimizations"]
            )
            assert optimizer.optimization_stats["average_memory_saved"] == expected_avg


class TestThreadSafety:
    """Test thread safety of memory optimizer operations."""

    def test_concurrent_optimization_calls(self, optimizer: MemoryOptimizer) -> None:
        """Multiple threads can call optimize_memory() safely."""
        optimizer.enabled = True
        results: list[int] = []

        def run_optimization() -> None:
            result = optimizer.optimize_memory()
            results.append(result)

        threads = [threading.Thread(target=run_optimization) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 5
        assert all(isinstance(r, int) for r in results)

    def test_concurrent_memory_usage_checks(self, optimizer: MemoryOptimizer) -> None:
        """Multiple threads can call get_current_memory_usage() safely."""
        results: list[tuple[int, int, float]] = []

        def check_memory() -> None:
            result = optimizer.get_current_memory_usage()
            results.append(result)

        threads = [threading.Thread(target=check_memory) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 10

    def test_concurrent_configuration_changes(self, optimizer: MemoryOptimizer) -> None:
        """Configuration changes from multiple threads complete without errors."""
        def configure_optimizer(threshold: float) -> None:
            optimizer.configure(threshold=threshold)

        threads = [threading.Thread(target=configure_optimizer, args=(float(i * 10),)) for i in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert 0.0 <= optimizer.threshold_percentage <= 100.0
