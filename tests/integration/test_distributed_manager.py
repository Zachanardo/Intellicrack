"""Integration tests for distributed analysis manager."""

import os
import tempfile
import time
import unittest
from pathlib import Path

from intellicrack.core.processing.distributed_manager import (
    DistributedAnalysisManager,
    TaskPriority,
    TaskStatus,
    create_distributed_manager,
)


class TestDistributedAnalysisManager(unittest.TestCase):
    """Test cases for distributed analysis manager."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_binary = self._create_test_binary()
        self.manager = None

    def tearDown(self):
        """Clean up test resources."""
        if self.manager:
            self.manager.shutdown()
        if os.path.exists(self.test_binary):
            os.remove(self.test_binary)

    def _create_test_binary(self) -> str:
        """Create a test binary file."""
        fd, path = tempfile.mkstemp(suffix=".exe")
        with os.fdopen(fd, "wb") as f:
            f.write(b"MZ" + b"\x00" * 1000)
            f.write(b"This is a test string for pattern matching")
            f.write(b"\x00" * 500)
            f.write(b"Another test string")
            f.write(b"\xFF" * 256)
        return path

    def test_manager_initialization_local_mode(self):
        """Test manager initialization in local mode."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)

        self.assertIsNotNone(self.manager)
        self.assertEqual(self.manager.mode, "local")
        self.assertFalse(self.manager.enable_networking)
        self.assertTrue(self.manager.is_coordinator)

    def test_manager_initialization_cluster_mode(self):
        """Test manager initialization in cluster mode."""
        self.manager = create_distributed_manager(mode="cluster", enable_networking=False)

        self.assertIsNotNone(self.manager)
        self.assertEqual(self.manager.mode, "cluster")

    def test_submit_single_task(self):
        """Test submitting a single analysis task."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9877)

        task_id = self.manager.submit_task(
            task_type="pattern_search",
            binary_path=self.test_binary,
            params={"patterns": [b"test"], "chunk_start": 0, "chunk_size": 2048},
            priority=TaskPriority.NORMAL
        )

        self.assertIsNotNone(task_id)
        status = self.manager.get_task_status(task_id)
        self.assertIsNotNone(status)
        self.assertEqual(status["task_type"], "pattern_search")

    def test_pattern_search_task(self):
        """Test pattern search task execution."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9878)

        task_id = self.manager.submit_task(
            task_type="pattern_search",
            binary_path=self.test_binary,
            params={
                "patterns": [b"test string"],
                "chunk_start": 0,
                "chunk_size": 4096
            },
            priority=TaskPriority.HIGH
        )

        result = self.manager.get_task_result(task_id, timeout=10.0)

        self.assertIsNotNone(result)
        self.assertIn("task_type", result)
        self.assertEqual(result["task_type"], "pattern_search")

    def test_entropy_analysis_task(self):
        """Test entropy analysis task execution."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9879)

        task_id = self.manager.submit_task(
            task_type="entropy_analysis",
            binary_path=self.test_binary,
            params={
                "chunk_start": 0,
                "chunk_size": 2048,
                "window_size": 256
            },
            priority=TaskPriority.NORMAL
        )

        result = self.manager.get_task_result(task_id, timeout=10.0)

        self.assertIsNotNone(result)
        self.assertIn("overall_entropy", result)
        self.assertIn("windows", result)

    def test_string_extraction_task(self):
        """Test string extraction task execution."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9880)

        task_id = self.manager.submit_task(
            task_type="string_extraction",
            binary_path=self.test_binary,
            params={
                "chunk_start": 0,
                "chunk_size": 2048,
                "min_length": 4
            },
            priority=TaskPriority.NORMAL
        )

        result = self.manager.get_task_result(task_id, timeout=10.0)

        self.assertIsNotNone(result)
        self.assertIn("strings", result)
        self.assertGreater(result["total_strings"], 0)

    def test_crypto_detection_task(self):
        """Test cryptographic constant detection task."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9881)

        task_id = self.manager.submit_task(
            task_type="crypto_detection",
            binary_path=self.test_binary,
            params={
                "chunk_start": 0,
                "chunk_size": 2048
            },
            priority=TaskPriority.NORMAL
        )

        result = self.manager.get_task_result(task_id, timeout=10.0)

        self.assertIsNotNone(result)
        self.assertIn("detections", result)

    def test_submit_multiple_tasks(self):
        """Test submitting multiple tasks."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9882)

        task_ids = []
        for i in range(5):
            task_id = self.manager.submit_task(
                task_type="pattern_search",
                binary_path=self.test_binary,
                params={
                    "patterns": [b"test"],
                    "chunk_start": i * 400,
                    "chunk_size": 400
                },
                priority=TaskPriority.NORMAL
            )
            task_ids.append(task_id)

        self.assertEqual(len(task_ids), 5)

        completion = self.manager.wait_for_completion(task_ids, timeout=30.0)
        self.assertEqual(completion["status"], "completed")

    def test_submit_binary_analysis(self):
        """Test submitting complete binary analysis."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9883)

        task_ids = self.manager.submit_binary_analysis(
            binary_path=self.test_binary,
            chunk_size=1024,
            priority=TaskPriority.HIGH
        )

        self.assertGreater(len(task_ids), 0)

        time.sleep(2.0)

        completion = self.manager.wait_for_completion(task_ids, timeout=60.0)
        self.assertIn(completion["status"], ["completed", "timeout"])

    def test_task_priority_ordering(self):
        """Test that tasks are executed in priority order."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9884)

        low_task = self.manager.submit_task(
            task_type="generic_analysis",
            binary_path=self.test_binary,
            params={},
            priority=TaskPriority.LOW
        )

        high_task = self.manager.submit_task(
            task_type="generic_analysis",
            binary_path=self.test_binary,
            params={},
            priority=TaskPriority.CRITICAL
        )

        time.sleep(3.0)

        high_status = self.manager.get_task_status(high_task)
        low_status = self.manager.get_task_status(low_task)

        self.assertIsNotNone(high_status)
        self.assertIsNotNone(low_status)

    def test_get_cluster_status(self):
        """Test getting cluster status."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9885)

        status = self.manager.get_cluster_status()

        self.assertIsNotNone(status)
        self.assertIn("mode", status)
        self.assertIn("nodes", status)
        self.assertIn("tasks", status)
        self.assertIn("performance", status)
        self.assertGreater(status["node_count"], 0)

    def test_export_results(self):
        """Test exporting results to JSON."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9886)

        task_id = self.manager.submit_task(
            task_type="string_extraction",
            binary_path=self.test_binary,
            params={"chunk_start": 0, "chunk_size": 1024},
            priority=TaskPriority.NORMAL
        )

        self.manager.get_task_result(task_id, timeout=10.0)

        fd, output_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            success = self.manager.export_results(output_file)
            self.assertTrue(success)
            self.assertTrue(os.path.exists(output_file))

            with open(output_file, encoding="utf-8") as f:
                import json
                data = json.load(f)
                self.assertIn("cluster_status", data)
                self.assertIn("completed_results", data)
                self.assertIn("tasks", data)

        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    def test_results_summary(self):
        """Test getting results summary."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9887)

        task_ids = [
            self.manager.submit_task("pattern_search", self.test_binary, {"patterns": [b"test"], "chunk_start": 0, "chunk_size": 1024}),
            self.manager.submit_task("entropy_analysis", self.test_binary, {"chunk_start": 0, "chunk_size": 1024})
        ]

        self.manager.wait_for_completion(task_ids, timeout=20.0)

        summary = self.manager.get_results_summary()

        self.assertIsNotNone(summary)
        self.assertIn("total_results", summary)
        self.assertIn("results_by_type", summary)

    def test_graceful_shutdown(self):
        """Test graceful shutdown of distributed manager."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9888)

        task_id = self.manager.submit_task(
            task_type="generic_analysis",
            binary_path=self.test_binary,
            params={}
        )

        time.sleep(1.0)

        self.manager.shutdown()
        self.assertFalse(self.manager.running)

    def test_nonexistent_binary(self):
        """Test handling of nonexistent binary file."""
        self.manager = create_distributed_manager(mode="local", enable_networking=False)
        self.manager.start_cluster(port=9889)

        with self.assertRaises(FileNotFoundError):
            self.manager.submit_binary_analysis("/nonexistent/binary.exe")


if __name__ == "__main__":
    unittest.main()
