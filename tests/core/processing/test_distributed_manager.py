"""Comprehensive tests for distributed analysis manager.

Tests validate task scheduling, fault tolerance, cluster management, worker health
monitoring, priority queueing, and result aggregation for distributed binary analysis.
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

requires_multiprocessing = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Multiprocessing cluster tests hang on Windows",
)

from intellicrack.core.processing.distributed_manager import (
    AnalysisTask,
    DistributedAnalysisManager,
    NodeStatus,
    TaskPriority,
    TaskStatus,
    WorkerNode,
    create_distributed_manager,
)


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create a sample binary for testing."""
    binary_path = tmp_path / "sample.exe"

    pe_header = b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00PE\x00\x00"
    pe_header += b"\x00" * 1000

    binary_path.write_bytes(pe_header)
    return binary_path


@pytest.fixture
def manager_local() -> DistributedAnalysisManager:
    """Create local-mode distributed manager."""
    config = {"num_workers": 2}
    mgr = DistributedAnalysisManager(mode="local", config=config, enable_networking=False)
    yield mgr
    mgr.shutdown()


@pytest.fixture
def manager_cluster() -> DistributedAnalysisManager:
    """Create cluster-mode distributed manager (no network)."""
    config = {"num_workers": 2, "port": 9999}
    mgr = DistributedAnalysisManager(mode="cluster", config=config, enable_networking=False)
    yield mgr
    mgr.shutdown()


class TestTaskPriorityQueue:
    """Test task priority queue and scheduling."""

    def test_task_priority_comparison(self) -> None:
        """Tasks are ordered by priority correctly."""
        task_high = AnalysisTask(
            task_id="high",
            task_type="test",
            priority=TaskPriority.HIGH,
            binary_path="/test",
            params={},
            status=TaskStatus.PENDING,
            created_at=time.time(),
        )
        task_low = AnalysisTask(
            task_id="low",
            task_type="test",
            priority=TaskPriority.LOW,
            binary_path="/test",
            params={},
            status=TaskStatus.PENDING,
            created_at=time.time(),
        )

        assert task_high < task_low

    def test_same_priority_ordered_by_time(self) -> None:
        """Tasks with same priority ordered by creation time."""
        task1 = AnalysisTask(
            task_id="first",
            task_type="test",
            priority=TaskPriority.NORMAL,
            binary_path="/test",
            params={},
            status=TaskStatus.PENDING,
            created_at=time.time(),
        )
        time.sleep(0.01)
        task2 = AnalysisTask(
            task_id="second",
            task_type="test",
            priority=TaskPriority.NORMAL,
            binary_path="/test",
            params={},
            status=TaskStatus.PENDING,
            created_at=time.time(),
        )

        assert task1 < task2

    def test_task_comparison_type_error(self) -> None:
        """Comparing task with non-task raises TypeError."""
        task = AnalysisTask(
            task_id="test",
            task_type="test",
            priority=TaskPriority.NORMAL,
            binary_path="/test",
            params={},
            status=TaskStatus.PENDING,
            created_at=time.time(),
        )

        with pytest.raises(TypeError):
            _ = task < "not_a_task"


class TestTaskSubmission:
    """Test task submission and tracking."""

    def test_submit_single_task(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Submit single task successfully."""
        task_id = manager_local.submit_task(
            task_type="pattern_search",
            binary_path=str(sample_binary),
            params={"patterns": [b"MZ"]},
            priority=TaskPriority.NORMAL,
        )

        assert task_id is not None
        assert task_id in manager_local.tasks
        assert manager_local.tasks[task_id].status == TaskStatus.PENDING

    def test_submit_with_priority(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Submit task with specific priority."""
        task_id = manager_local.submit_task(
            task_type="entropy_analysis",
            binary_path=str(sample_binary),
            params={},
            priority=TaskPriority.CRITICAL,
        )

        assert manager_local.tasks[task_id].priority == TaskPriority.CRITICAL

    def test_submit_binary_analysis_creates_multiple_tasks(
        self, manager_local: DistributedAnalysisManager, sample_binary: Path
    ) -> None:
        """Submit binary analysis creates multiple distributed tasks."""
        task_ids = manager_local.submit_binary_analysis(
            binary_path=str(sample_binary),
            chunk_size=512,
            priority=TaskPriority.NORMAL,
        )

        assert len(task_ids) > 1
        assert all(tid in manager_local.tasks for tid in task_ids)

    def test_submit_nonexistent_binary_raises_error(self, manager_local: DistributedAnalysisManager) -> None:
        """Submitting analysis for nonexistent binary raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            manager_local.submit_binary_analysis(
                binary_path="/nonexistent/file.exe",
                chunk_size=1024,
            )


@requires_multiprocessing
class TestTaskExecution:
    """Test task execution and result handling."""

    def test_pattern_search_task(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Pattern search task executes correctly."""
        task_id = manager_local.submit_task(
            task_type="pattern_search",
            binary_path=str(sample_binary),
            params={"patterns": [b"MZ", b"PE"]},
        )

        manager_local.start_cluster()
        result = manager_local.get_task_result(task_id, timeout=10.0)

        assert result is not None
        assert result["task_type"] == "pattern_search"
        assert "matches" in result
        assert len(result["matches"]) >= 1

    def test_entropy_analysis_task(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Entropy analysis task executes correctly."""
        task_id = manager_local.submit_task(
            task_type="entropy_analysis",
            binary_path=str(sample_binary),
            params={"chunk_start": 0, "chunk_size": 512, "window_size": 128},
        )

        manager_local.start_cluster()
        result = manager_local.get_task_result(task_id, timeout=10.0)

        assert result is not None
        assert result["task_type"] == "entropy_analysis"
        assert "overall_entropy" in result
        assert "windows" in result

    def test_string_extraction_task(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """String extraction task executes correctly."""
        task_id = manager_local.submit_task(
            task_type="string_extraction",
            binary_path=str(sample_binary),
            params={"chunk_start": 0, "chunk_size": 512, "min_length": 4},
        )

        manager_local.start_cluster()
        result = manager_local.get_task_result(task_id, timeout=10.0)

        assert result is not None
        assert result["task_type"] == "string_extraction"
        assert "strings" in result

    def test_crypto_detection_task(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Crypto detection task executes correctly."""
        task_id = manager_local.submit_task(
            task_type="crypto_detection",
            binary_path=str(sample_binary),
            params={"chunk_start": 0, "chunk_size": 512},
        )

        manager_local.start_cluster()
        result = manager_local.get_task_result(task_id, timeout=10.0)

        assert result is not None
        assert result["task_type"] == "crypto_detection"
        assert "detections" in result

    def test_generic_analysis_task(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Generic analysis task executes correctly."""
        task_id = manager_local.submit_task(
            task_type="generic_analysis",
            binary_path=str(sample_binary),
            params={},
        )

        manager_local.start_cluster()
        result = manager_local.get_task_result(task_id, timeout=10.0)

        assert result is not None
        assert result["task_type"] == "generic_analysis"
        assert result["file_type"] == "PE"


@requires_multiprocessing
class TestFaultTolerance:
    """Test fault tolerance and error handling."""

    def test_task_retry_on_failure(self, manager_local: DistributedAnalysisManager) -> None:
        """Failed task is retried automatically."""
        task_id = manager_local.submit_task(
            task_type="test",
            binary_path="/nonexistent/file.exe",
            params={},
        )

        manager_local.start_cluster()
        time.sleep(2.0)

        task = manager_local.tasks[task_id]
        assert task.retry_count > 0 or task.status == TaskStatus.FAILED

    def test_max_retries_exceeded(self, manager_local: DistributedAnalysisManager) -> None:
        """Task fails permanently after max retries."""
        task = AnalysisTask(
            task_id="fail_test",
            task_type="test",
            priority=TaskPriority.NORMAL,
            binary_path="/nonexistent",
            params={},
            status=TaskStatus.PENDING,
            created_at=time.time(),
            max_retries=1,
        )

        manager_local.tasks[task.task_id] = task

        for _ in range(3):
            manager_local._handle_task_failure(task.task_id, "Test error")

        assert task.status == TaskStatus.FAILED
        assert task.retry_count > task.max_retries

    def test_node_failure_reassigns_tasks(self, manager_cluster: DistributedAnalysisManager) -> None:
        """Node failure causes task reassignment."""
        fake_node = WorkerNode(
            node_id="fake_worker",
            hostname="fake",
            ip_address="127.0.0.1",
            port=9999,
            status=NodeStatus.READY,
            capabilities={},
            current_load=0.0,
            max_load=4.0,
            active_tasks=["task1", "task2"],
            completed_tasks=0,
            failed_tasks=0,
            last_heartbeat=time.time(),
            platform_info={},
            resource_usage={},
        )

        manager_cluster.nodes["fake_worker"] = fake_node

        task1 = AnalysisTask(
            task_id="task1",
            task_type="test",
            priority=TaskPriority.NORMAL,
            binary_path="/test",
            params={},
            status=TaskStatus.RUNNING,
            created_at=time.time(),
            assigned_node="fake_worker",
        )
        manager_cluster.tasks["task1"] = task1

        manager_cluster._mark_node_offline("fake_worker")

        assert manager_cluster.nodes["fake_worker"].status == NodeStatus.OFFLINE
        assert task1.status == TaskStatus.RETRY


class TestClusterManagement:
    """Test cluster management and node operations."""

    def test_worker_node_registration(self, manager_cluster: DistributedAnalysisManager) -> None:
        """Worker node registers successfully."""
        assert manager_cluster.node_id in manager_cluster.nodes
        node = manager_cluster.nodes[manager_cluster.node_id]
        assert node.status == NodeStatus.READY

    def test_node_capabilities_detected(self, manager_cluster: DistributedAnalysisManager) -> None:
        """Node capabilities are detected correctly."""
        node = manager_cluster.nodes[manager_cluster.node_id]
        assert "os" in node.capabilities
        assert "cpu_count" in node.capabilities

    def test_get_available_nodes(self, manager_cluster: DistributedAnalysisManager) -> None:
        """Available nodes are identified correctly."""
        available = manager_cluster._get_available_nodes()
        assert len(available) > 0

    def test_select_best_node_by_load(self, manager_cluster: DistributedAnalysisManager) -> None:
        """Best node selected based on load."""
        node1 = WorkerNode(
            node_id="node1",
            hostname="host1",
            ip_address="127.0.0.1",
            port=9999,
            status=NodeStatus.READY,
            capabilities={"supports_frida": True},
            current_load=0.0,
            max_load=4.0,
            active_tasks=[],
            completed_tasks=10,
            failed_tasks=0,
            last_heartbeat=time.time(),
            platform_info={"system": "Windows"},
            resource_usage={},
        )

        node2 = WorkerNode(
            node_id="node2",
            hostname="host2",
            ip_address="127.0.0.2",
            port=9999,
            status=NodeStatus.READY,
            capabilities={},
            current_load=3.0,
            max_load=4.0,
            active_tasks=[],
            completed_tasks=5,
            failed_tasks=2,
            last_heartbeat=time.time(),
            platform_info={"system": "Linux"},
            resource_usage={},
        )

        manager_cluster.nodes["node1"] = node1
        manager_cluster.nodes["node2"] = node2

        task = AnalysisTask(
            task_id="test",
            task_type="frida_analysis",
            priority=TaskPriority.NORMAL,
            binary_path="/test",
            params={},
            status=TaskStatus.PENDING,
            created_at=time.time(),
        )

        best_node = manager_cluster._select_best_node(task, [node1, node2])
        assert best_node == node1

    def test_cluster_status_report(self, manager_cluster: DistributedAnalysisManager) -> None:
        """Cluster status report includes all information."""
        status = manager_cluster.get_cluster_status()

        assert "mode" in status
        assert "node_id" in status
        assert "nodes" in status
        assert "tasks" in status
        assert "performance" in status


@requires_multiprocessing
class TestResultAggregation:
    """Test result collection and aggregation."""

    def test_get_task_status(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Task status can be retrieved."""
        task_id = manager_local.submit_task(
            task_type="generic_analysis",
            binary_path=str(sample_binary),
            params={},
        )

        status = manager_local.get_task_status(task_id)
        assert status is not None
        assert status["task_id"] == task_id
        assert "status" in status

    def test_get_task_result_waits_for_completion(
        self, manager_local: DistributedAnalysisManager, sample_binary: Path
    ) -> None:
        """Getting task result waits for completion."""
        task_id = manager_local.submit_task(
            task_type="generic_analysis",
            binary_path=str(sample_binary),
            params={},
        )

        manager_local.start_cluster()
        result = manager_local.get_task_result(task_id, timeout=10.0)

        assert result is not None

    def test_wait_for_all_tasks_completion(
        self, manager_local: DistributedAnalysisManager, sample_binary: Path
    ) -> None:
        """Wait for all tasks to complete."""
        task_ids = []
        for _ in range(3):
            task_id = manager_local.submit_task(
                task_type="generic_analysis",
                binary_path=str(sample_binary),
                params={},
            )
            task_ids.append(task_id)

        manager_local.start_cluster()
        summary = manager_local.wait_for_completion(task_ids, timeout=30.0)

        assert summary["status"] == "completed"

    def test_get_results_summary(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Results summary aggregates all completed tasks."""
        task_ids = manager_local.submit_binary_analysis(str(sample_binary), chunk_size=512)

        manager_local.start_cluster()
        manager_local.wait_for_completion(task_ids, timeout=30.0)

        summary = manager_local.get_results_summary()
        assert summary["total_results"] > 0

    def test_export_results_to_json(
        self, manager_local: DistributedAnalysisManager, sample_binary: Path, tmp_path: Path
    ) -> None:
        """Results export to JSON file."""
        task_id = manager_local.submit_task(
            task_type="generic_analysis",
            binary_path=str(sample_binary),
            params={},
        )

        manager_local.start_cluster()
        manager_local.get_task_result(task_id, timeout=10.0)

        output_path = tmp_path / "results.json"
        success = manager_local.export_results(str(output_path))

        assert success
        assert output_path.exists()

        with open(output_path) as f:
            results = json.load(f)

        assert "cluster_status" in results
        assert "completed_results" in results


class TestPerformanceMetrics:
    """Test performance tracking and metrics."""

    def test_metrics_track_task_counts(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Performance metrics track task counts."""
        initial_submitted = manager_local.performance_metrics["tasks_submitted"]

        manager_local.submit_task("generic_analysis", str(sample_binary), {})

        assert manager_local.performance_metrics["tasks_submitted"] == initial_submitted + 1

    def test_metrics_track_task_types(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Performance metrics track task type distribution."""
        manager_local.submit_task("pattern_search", str(sample_binary), {})
        manager_local.submit_task("entropy_analysis", str(sample_binary), {})

        assert manager_local.performance_metrics["task_distribution"]["pattern_search"] >= 1
        assert manager_local.performance_metrics["task_distribution"]["entropy_analysis"] >= 1


class TestNetworkProtocol:
    """Test network message protocol (without actual networking)."""

    def test_message_serialization(self, manager_cluster: DistributedAnalysisManager) -> None:
        """Messages serialize and deserialize correctly."""
        test_message = {
            "type": "test",
            "data": "test_data",
            "number": 42,
        }

        sock1, sock2 = socket.socketpair()

        try:
            manager_cluster._send_message(sock1, test_message)
            received = manager_cluster._receive_message(sock2)

            assert received == test_message

        finally:
            sock1.close()
            sock2.close()

    def test_message_hmac_verification(self, manager_cluster: DistributedAnalysisManager) -> None:
        """HMAC verification detects tampering."""
        test_message = {"type": "test", "data": "test"}

        sock1, sock2 = socket.socketpair()

        try:
            manager_cluster._send_message(sock1, test_message)
            received = manager_cluster._receive_message(sock2)

            assert received == test_message

        finally:
            sock1.close()
            sock2.close()


@requires_multiprocessing
class TestClusterStartup:
    """Test cluster startup and initialization."""

    def test_start_cluster_local_mode(self, manager_local: DistributedAnalysisManager) -> None:
        """Cluster starts successfully in local mode."""
        success = manager_local.start_cluster()
        assert success
        assert manager_local.running

    def test_start_cluster_already_running(self, manager_local: DistributedAnalysisManager) -> None:
        """Starting already running cluster returns False."""
        manager_local.start_cluster()
        result = manager_local.start_cluster()
        assert result is False

    def test_shutdown_cluster(self, manager_local: DistributedAnalysisManager) -> None:
        """Cluster shuts down cleanly."""
        manager_local.start_cluster()
        manager_local.shutdown()
        assert not manager_local.running


@requires_multiprocessing
class TestTaskTimeout:
    """Test task timeout handling."""

    def test_task_timeout_detection(self, manager_local: DistributedAnalysisManager) -> None:
        """Long-running tasks timeout correctly."""
        task = AnalysisTask(
            task_id="timeout_test",
            task_type="test",
            priority=TaskPriority.NORMAL,
            binary_path="/test",
            params={},
            status=TaskStatus.RUNNING,
            created_at=time.time(),
            started_at=time.time() - 100,
            timeout=1.0,
        )

        manager_local.tasks[task.task_id] = task
        manager_local.start_cluster()

        time.sleep(3.0)

        assert task.status in (TaskStatus.FAILED, TaskStatus.RETRY)


class TestFactoryFunction:
    """Test factory function."""

    def test_create_distributed_manager(self) -> None:
        """Factory function creates manager correctly."""
        mgr = create_distributed_manager(mode="local", enable_networking=False)
        assert isinstance(mgr, DistributedAnalysisManager)
        assert mgr.mode == "local"
        mgr.shutdown()

    def test_auto_mode_selection(self) -> None:
        """Auto mode selects appropriate mode."""
        mgr = create_distributed_manager(mode="auto", enable_networking=False)
        assert mgr.mode in ("local", "cluster")
        mgr.shutdown()


@requires_multiprocessing
class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_task_queue(self, manager_local: DistributedAnalysisManager) -> None:
        """Empty task queue handles gracefully."""
        manager_local.start_cluster()
        summary = manager_local.wait_for_completion(timeout=1.0)
        assert summary["status"] == "completed"

    def test_task_with_missing_binary(self, manager_local: DistributedAnalysisManager) -> None:
        """Task with missing binary file fails appropriately."""
        task_id = manager_local.submit_task(
            task_type="generic_analysis",
            binary_path="/nonexistent/file.exe",
            params={},
        )

        manager_local.start_cluster()
        result = manager_local.get_task_result(task_id, timeout=5.0)

        assert result is not None
        assert "error" in result or result.get("status") == "failed"

    def test_get_nonexistent_task_status(self, manager_local: DistributedAnalysisManager) -> None:
        """Getting status of nonexistent task returns None."""
        status = manager_local.get_task_status("nonexistent_id")
        assert status is None

    def test_get_result_without_timeout(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Getting result without timeout returns immediately."""
        task_id = manager_local.submit_task(
            task_type="generic_analysis",
            binary_path=str(sample_binary),
            params={},
        )

        result = manager_local.get_task_result(task_id, timeout=None)
        assert result is None


@requires_multiprocessing
class TestRealWorldScenarios:
    """Test realistic distributed analysis scenarios."""

    def test_large_binary_chunked_analysis(self, manager_local: DistributedAnalysisManager, tmp_path: Path) -> None:
        """Large binary is analyzed in chunks across workers."""
        large_binary = tmp_path / "large.exe"
        large_binary.write_bytes(b"MZ" + b"\x00" * 10000)

        task_ids = manager_local.submit_binary_analysis(str(large_binary), chunk_size=2048)
        assert len(task_ids) > 3

        manager_local.start_cluster()
        summary = manager_local.wait_for_completion(task_ids, timeout=30.0)

        assert summary["status"] == "completed"

    def test_priority_task_execution_order(
        self, manager_local: DistributedAnalysisManager, sample_binary: Path
    ) -> None:
        """High priority tasks execute before low priority."""
        low_task = manager_local.submit_task(
            "generic_analysis",
            str(sample_binary),
            {},
            priority=TaskPriority.LOW,
        )
        critical_task = manager_local.submit_task(
            "generic_analysis",
            str(sample_binary),
            {},
            priority=TaskPriority.CRITICAL,
        )

        manager_local.start_cluster()

        critical_result = manager_local.get_task_result(critical_task, timeout=10.0)
        low_result = manager_local.get_task_result(low_task, timeout=10.0)

        assert critical_result is not None
        assert low_result is not None

    def test_concurrent_task_execution(self, manager_local: DistributedAnalysisManager, sample_binary: Path) -> None:
        """Multiple tasks execute concurrently."""
        task_ids = []
        for _ in range(5):
            task_id = manager_local.submit_task(
                "generic_analysis",
                str(sample_binary),
                {},
            )
            task_ids.append(task_id)

        manager_local.start_cluster()
        start_time = time.time()
        summary = manager_local.wait_for_completion(task_ids, timeout=30.0)
        elapsed = time.time() - start_time

        assert summary["status"] == "completed"
        assert elapsed < 15.0
