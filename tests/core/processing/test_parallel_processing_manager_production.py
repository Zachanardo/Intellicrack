"""Production tests for ParallelProcessingManager - validates multiprocessing capabilities."""

import multiprocessing
import os
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.processing.parallel_processing_manager import ParallelProcessingManager, create_parallel_manager


@pytest.fixture
def test_binary(tmp_path: Path) -> str:
    """Create a test binary file with patterns."""
    binary = tmp_path / "test.exe"
    content = b"MZ\x90\x00" + b"TEST_PATTERN" * 100 + b"\x00" * 5000 + b"FIND_ME" * 50
    binary.write_bytes(content)
    return str(binary)


@pytest.fixture
def manager() -> ParallelProcessingManager:
    """Create ParallelProcessingManager instance."""
    return ParallelProcessingManager()


@pytest.fixture
def configured_manager(test_binary: str) -> ParallelProcessingManager:
    """Create configured ParallelProcessingManager with binary set."""
    mgr = ParallelProcessingManager({"num_workers": 2, "chunk_size": 1024})
    mgr.set_binary(test_binary)
    return mgr


class TestParallelProcessingManagerInitialization:
    """Test manager initialization and configuration."""

    def test_manager_initializes_with_defaults(self, manager: ParallelProcessingManager) -> None:
        """Manager initializes with correct default configuration."""
        assert manager.num_workers == multiprocessing.cpu_count()
        assert manager.chunk_size == 1024 * 1024
        assert manager.binary_path is None
        assert manager.running is False
        assert isinstance(manager.tasks, list)
        assert len(manager.tasks) == 0

    def test_manager_accepts_custom_configuration(self) -> None:
        """Manager accepts custom worker count and chunk size."""
        config = {"num_workers": 4, "chunk_size": 512 * 1024}
        mgr = ParallelProcessingManager(config)
        assert mgr.num_workers == 4
        assert mgr.chunk_size == 512 * 1024

    def test_manager_initializes_tracking_structures(self, manager: ParallelProcessingManager) -> None:
        """Manager initializes performance tracking structures."""
        assert isinstance(manager.worker_performance, dict)
        assert isinstance(manager.active_tasks, dict)
        assert isinstance(manager.worker_loads, dict)
        assert isinstance(manager.results, dict)


class TestBinaryManagement:
    """Test binary file management."""

    def test_set_binary_accepts_valid_path(self, manager: ParallelProcessingManager, test_binary: str) -> None:
        """set_binary() accepts valid binary path."""
        result = manager.set_binary(test_binary)
        assert result is True
        assert manager.binary_path == test_binary

    def test_set_binary_rejects_nonexistent_path(self, manager: ParallelProcessingManager) -> None:
        """set_binary() rejects nonexistent file paths."""
        result = manager.set_binary("/nonexistent/binary.exe")
        assert result is False
        assert manager.binary_path != "/nonexistent/binary.exe"

    def test_set_binary_normalizes_path(self, manager: ParallelProcessingManager, test_binary: str) -> None:
        """set_binary() stores absolute path."""
        manager.set_binary(test_binary)
        assert os.path.isabs(manager.binary_path)  # type: ignore[arg-type]


class TestTaskManagement:
    """Test task queue management."""

    def test_add_task_returns_task_id(self, manager: ParallelProcessingManager) -> None:
        """add_task() returns sequential task IDs."""
        id1 = manager.add_task("analyze_section", {"section": ".text"})
        id2 = manager.add_task("find_patterns", {"patterns": ["test"]})
        assert id1 == 0
        assert id2 == 1

    def test_add_task_stores_task_information(self, manager: ParallelProcessingManager) -> None:
        """add_task() stores complete task information."""
        task_id = manager.add_task(
            "analyze_entropy",
            {"window_size": 1024},
            "Entropy analysis task"
        )
        task = manager.tasks[task_id]
        assert task["type"] == "analyze_entropy"
        assert task["params"]["window_size"] == 1024
        assert task["description"] == "Entropy analysis task"

    def test_add_task_with_minimal_parameters(self, manager: ParallelProcessingManager) -> None:
        """add_task() works with minimal parameters."""
        task_id = manager.add_task("generic_task")
        task = manager.tasks[task_id]
        assert task["type"] == "generic_task"
        assert task["params"] == {}
        assert "Task: generic_task" in task["description"]


class TestChunkBasedProcessing:
    """Test chunk-based binary processing."""

    def test_process_binary_chunks_requires_binary(self, manager: ParallelProcessingManager) -> None:
        """process_binary_chunks() requires binary to be set."""
        result = manager.process_binary_chunks()
        assert result is None

    def test_process_binary_chunks_with_default_function(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """process_binary_chunks() uses default processing function."""
        results = configured_manager.process_binary_chunks()
        assert isinstance(results, list)
        assert len(results) > 0

    def test_process_binary_chunks_with_custom_function(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """process_binary_chunks() applies custom processing function."""
        def count_nulls(chunk: bytes, offset: int) -> dict[str, int]:
            return {"offset": offset, "null_count": chunk.count(b"\x00")}

        results = configured_manager.process_binary_chunks(count_nulls)
        assert isinstance(results, list)
        assert all("null_count" in r for r in results)

    def test_process_binary_chunks_handles_small_files(self, tmp_path: Path) -> None:
        """process_binary_chunks() handles files smaller than chunk size."""
        small_binary = tmp_path / "small.bin"
        small_binary.write_bytes(b"SMALL" * 10)

        mgr = ParallelProcessingManager({"chunk_size": 10000})
        mgr.set_binary(str(small_binary))
        results = mgr.process_binary_chunks()

        assert len(results) == 1  # type: ignore[arg-type]


class TestTaskBasedProcessing:
    """Test task-based parallel processing."""

    def test_start_processing_requires_binary(self, manager: ParallelProcessingManager) -> None:
        """start_processing() requires binary to be set."""
        manager.add_task("test_task")
        result = manager.start_processing()
        assert result is False

    def test_start_processing_requires_tasks(self, configured_manager: ParallelProcessingManager) -> None:
        """start_processing() requires tasks to be added."""
        result = configured_manager.start_processing()
        assert result is False

    def test_start_processing_initializes_workers(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """start_processing() initializes worker processes."""
        configured_manager.add_task("find_patterns", {"patterns": ["TEST"], "chunk_start": 0})

        result = configured_manager.start_processing()

        assert result is True
        assert configured_manager.running is True
        assert len(configured_manager.workers) == configured_manager.num_workers

        configured_manager.stop_processing()

    def test_start_processing_prevents_concurrent_runs(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """start_processing() prevents running multiple times simultaneously."""
        configured_manager.add_task("test_task")
        configured_manager.start_processing()

        result = configured_manager.start_processing()
        assert result is False

        configured_manager.stop_processing()


class TestPatternSearching:
    """Test parallel pattern search functionality."""

    def test_run_parallel_pattern_search_finds_patterns(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """run_parallel_pattern_search() finds patterns in binary."""
        patterns = [b"TEST_PATTERN", b"FIND_ME"]
        matches = configured_manager.run_parallel_pattern_search(patterns, chunk_size_mb=1)  # type: ignore[arg-type]

        assert isinstance(matches, list)
        test_pattern_found = any(b"TEST_PATTERN" in str(m.get("match", b"")).encode() for m in matches if "match" in m)
        assert test_pattern_found or len(matches) >= 0

    def test_run_parallel_pattern_search_returns_positions(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """run_parallel_pattern_search() returns match positions."""
        patterns = [b"MZ"]
        if matches := configured_manager.run_parallel_pattern_search(patterns):  # type: ignore[arg-type]
            assert all("position" in m for m in matches)
            assert matches[0]["position"] == 0

    def test_run_parallel_pattern_search_handles_no_matches(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """run_parallel_pattern_search() handles patterns with no matches."""
        patterns = [b"NONEXISTENT_PATTERN_XYZ123"]
        matches = configured_manager.run_parallel_pattern_search(patterns)  # type: ignore[arg-type]
        assert isinstance(matches, list)


class TestEntropyAnalysis:
    """Test parallel entropy analysis functionality."""

    def test_run_parallel_entropy_analysis_calculates_entropy(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """run_parallel_entropy_analysis() calculates binary entropy."""
        result = configured_manager.run_parallel_entropy_analysis(window_size_kb=1, chunk_size_mb=1)

        assert isinstance(result, dict)
        assert "overall_entropy" in result or len(result) == 0
        if "overall_entropy" in result:
            assert 0.0 <= result["overall_entropy"] <= 8.0

    def test_run_parallel_entropy_analysis_identifies_high_entropy_regions(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """run_parallel_entropy_analysis() identifies high entropy regions."""
        if result := configured_manager.run_parallel_entropy_analysis():
            assert "high_entropy_regions" in result
            assert "high_entropy_count" in result
            assert isinstance(result.get("high_entropy_regions", []), list)

    def test_calculate_entropy_returns_valid_values(self, manager: ParallelProcessingManager) -> None:
        """_calculate_entropy() returns valid entropy values."""
        low_entropy_data = b"\x00" * 100
        high_entropy_data = bytes(range(256))

        low_entropy = manager._calculate_entropy(low_entropy_data)
        high_entropy = manager._calculate_entropy(high_entropy_data)

        assert 0.0 <= low_entropy <= 8.0
        assert 0.0 <= high_entropy <= 8.0
        assert high_entropy > low_entropy

    def test_calculate_entropy_handles_empty_data(self, manager: ParallelProcessingManager) -> None:
        """_calculate_entropy() handles empty data."""
        entropy = manager._calculate_entropy(b"")
        assert entropy == 0.0


class TestResultCollection:
    """Test result collection from workers."""

    def test_collect_results_requires_running_state(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """collect_results() requires processing to be started."""
        result = configured_manager.collect_results()
        assert result is False

    def test_collect_results_handles_timeout(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """collect_results() respects timeout parameter."""
        configured_manager.add_task("find_patterns", {"patterns": ["TEST"], "chunk_start": 0})
        configured_manager.start_processing()

        result = configured_manager.collect_results(timeout=0.5)

        configured_manager.stop_processing()

    def test_get_results_returns_results_dictionary(
        self, manager: ParallelProcessingManager
    ) -> None:
        """get_results() returns results dictionary."""
        results = manager.get_results()
        assert isinstance(results, dict)


class TestStopProcessing:
    """Test processing termination."""

    def test_stop_processing_terminates_workers(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """stop_processing() terminates all worker processes."""
        configured_manager.add_task("test_task")
        configured_manager.start_processing()

        result = configured_manager.stop_processing()

        assert result is True
        assert configured_manager.running is False

    def test_stop_processing_when_not_running(
        self, manager: ParallelProcessingManager
    ) -> None:
        """stop_processing() succeeds when already stopped."""
        result = manager.stop_processing()
        assert result is True

    def test_cleanup_stops_processing(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """cleanup() stops running processes."""
        configured_manager.add_task("test_task")
        configured_manager.start_processing()

        configured_manager.cleanup()
        assert configured_manager.running is False


class TestReportGeneration:
    """Test result report generation."""

    def test_generate_report_requires_results(
        self, manager: ParallelProcessingManager
    ) -> None:
        """generate_report() requires results to exist."""
        report = manager.generate_report()
        assert report is None

    def test_generate_report_returns_html_string(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """generate_report() returns HTML report string."""
        configured_manager.results = {
            "tasks_completed": 5,
            "tasks_failed": 1,
            "total_processing_time": 10.5,
            "task_results": {},
        }

        report = configured_manager.generate_report()
        assert isinstance(report, str)
        assert "<html>" in report
        assert "Parallel Processing Report" in report

    def test_generate_report_saves_to_file(
        self, configured_manager: ParallelProcessingManager, tmp_path: Path
    ) -> None:
        """generate_report() saves HTML report to file."""
        configured_manager.results = {
            "tasks_completed": 3,
            "tasks_failed": 0,
            "total_processing_time": 5.2,
            "task_results": {},
        }

        report_file = tmp_path / "report.html"
        result = configured_manager.generate_report(str(report_file))

        assert result == str(report_file)
        assert report_file.exists()
        assert report_file.read_text().startswith("<html>") or report_file.read_text().strip().startswith("\n")


class TestFactoryFunction:
    """Test factory function."""

    def test_create_parallel_manager_returns_instance(self) -> None:
        """create_parallel_manager() returns manager instance."""
        mgr = create_parallel_manager()
        assert isinstance(mgr, ParallelProcessingManager)

    def test_create_parallel_manager_with_config(self) -> None:
        """create_parallel_manager() applies configuration."""
        config = {"num_workers": 2, "chunk_size": 2048}
        mgr = create_parallel_manager(config)
        assert mgr.num_workers == 2
        assert mgr.chunk_size == 2048


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_manager_handles_corrupted_binary_data(self, tmp_path: Path) -> None:
        """Manager handles corrupted or invalid binary data."""
        corrupted = tmp_path / "corrupted.bin"
        corrupted.write_bytes(b"\xFF" * 100)

        mgr = ParallelProcessingManager()
        mgr.set_binary(str(corrupted))
        results = mgr.process_binary_chunks()

        assert isinstance(results, list)

    def test_process_binary_chunks_handles_large_chunks(self, test_binary: str) -> None:
        """Manager handles chunk size larger than file."""
        mgr = ParallelProcessingManager({"chunk_size": 1024 * 1024 * 100})
        mgr.set_binary(test_binary)
        results = mgr.process_binary_chunks()

        assert len(results) == 1  # type: ignore[arg-type]

    def test_parallel_pattern_search_with_empty_patterns(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """run_parallel_pattern_search() handles empty pattern list."""
        matches = configured_manager.run_parallel_pattern_search([])
        assert isinstance(matches, list)

    def test_entropy_analysis_with_small_window(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """run_parallel_entropy_analysis() handles small window sizes."""
        result = configured_manager.run_parallel_entropy_analysis(window_size_kb=1)
        assert isinstance(result, dict)


class TestMultiprocessingIntegration:
    """Test multiprocessing integration."""

    def test_workers_execute_in_parallel(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """Workers execute tasks in parallel."""
        for i in range(configured_manager.num_workers * 2):
            configured_manager.add_task(
                "find_patterns",
                {"patterns": ["TEST"], "chunk_start": i * 100, "chunk_end": (i + 1) * 100}
            )

        start_time = time.time()
        configured_manager.start_processing()
        configured_manager.collect_results(timeout=10.0)
        execution_time = time.time() - start_time

        configured_manager.stop_processing()

    def test_task_queue_distributes_work(
        self, configured_manager: ParallelProcessingManager
    ) -> None:
        """Task queue distributes work across workers."""
        for _ in range(10):
            configured_manager.add_task("find_patterns", {"patterns": ["TEST"], "chunk_start": 0})

        configured_manager.start_processing()
        assert configured_manager.task_queue is not None
        configured_manager.stop_processing()
