"""Production tests for model performance monitor.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import json
import tempfile
import time
from datetime import datetime
from pathlib import Path
from collections.abc import Generator
from typing import Any

import pytest

from intellicrack.ai.model_performance_monitor import (
    ModelBenchmark,
    ModelPerformanceMonitor,
    PerformanceMetrics,
    get_performance_monitor,
)


class TestPerformanceMetrics:
    """Test PerformanceMetrics dataclass."""

    def test_metrics_creation(self) -> None:
        """PerformanceMetrics can be created with all fields."""
        now = datetime.now()
        metrics = PerformanceMetrics(
            model_id="test-model",
            timestamp=now,
            inference_time=0.5,
            tokens_generated=100,
            tokens_per_second=200.0,
            memory_used_mb=500.0,
            gpu_memory_mb=1000.0,
            cpu_percent=50.0,
            gpu_percent=75.0,
            batch_size=4,
            sequence_length=512,
            quantization="int8",
            device="cuda",
            error=None
        )

        assert metrics.model_id == "test-model"
        assert metrics.timestamp == now
        assert metrics.inference_time == 0.5
        assert metrics.tokens_generated == 100
        assert metrics.tokens_per_second == 200.0
        assert metrics.memory_used_mb == 500.0
        assert metrics.gpu_memory_mb == 1000.0
        assert metrics.batch_size == 4
        assert metrics.sequence_length == 512
        assert metrics.quantization == "int8"
        assert metrics.device == "cuda"
        assert metrics.error is None

    def test_metrics_with_error(self) -> None:
        """PerformanceMetrics can record error information."""
        metrics = PerformanceMetrics(
            model_id="failed-model",
            timestamp=datetime.now(),
            inference_time=0.1,
            tokens_generated=0,
            tokens_per_second=0.0,
            memory_used_mb=100.0,
            gpu_memory_mb=0.0,
            cpu_percent=10.0,
            gpu_percent=0.0,
            batch_size=1,
            sequence_length=0,
            error="OOM error during inference"
        )

        assert metrics.error == "OOM error during inference"
        assert metrics.tokens_generated == 0


class TestModelBenchmark:
    """Test ModelBenchmark dataclass."""

    def test_benchmark_creation(self) -> None:
        """ModelBenchmark can be created with statistics."""
        benchmark = ModelBenchmark(
            model_id="benchmark-model",
            avg_tokens_per_second=150.0,
            avg_inference_time=0.6,
            avg_memory_mb=750.0,
            p50_latency=0.5,
            p95_latency=1.2,
            p99_latency=1.8,
            total_inferences=1000,
            total_tokens=150000,
            error_rate=0.05,
            device="cuda",
            quantization="int8"
        )

        assert benchmark.model_id == "benchmark-model"
        assert benchmark.avg_tokens_per_second == 150.0
        assert benchmark.p50_latency == 0.5
        assert benchmark.p95_latency == 1.2
        assert benchmark.p99_latency == 1.8
        assert benchmark.total_inferences == 1000
        assert benchmark.total_tokens == 150000
        assert benchmark.error_rate == 0.05

    def test_benchmark_default_date(self) -> None:
        """ModelBenchmark has default benchmark date."""
        benchmark = ModelBenchmark(
            model_id="test-model",
            avg_tokens_per_second=100.0,
            avg_inference_time=0.5,
            avg_memory_mb=500.0,
            p50_latency=0.4,
            p95_latency=1.0,
            p99_latency=1.5,
            total_inferences=100,
            total_tokens=10000,
            error_rate=0.0,
            device="cpu"
        )

        assert isinstance(benchmark.benchmark_date, datetime)


class TestModelPerformanceMonitor:
    """Test ModelPerformanceMonitor functionality."""

    @pytest.fixture
    def temp_save_dir(self) -> Generator[Path, None, None]:
        """Create temporary save directory."""
        temp_dir = tempfile.mkdtemp(prefix="perf_monitor_test_")
        save_path = Path(temp_dir)
        yield save_path
        import shutil
        shutil.rmtree(save_path, ignore_errors=True)

    @pytest.fixture
    def monitor(self, temp_save_dir: Path) -> ModelPerformanceMonitor:
        """Create performance monitor with temp directory."""
        return ModelPerformanceMonitor(history_size=100, save_dir=str(temp_save_dir))

    def test_monitor_initialization(self, temp_save_dir: Path) -> None:
        """Performance monitor initializes correctly."""
        monitor = ModelPerformanceMonitor(save_dir=str(temp_save_dir))

        assert monitor.save_dir == temp_save_dir
        assert temp_save_dir.exists()
        assert monitor.history_size > 0
        assert isinstance(monitor.metrics_history, dict)
        assert isinstance(monitor.benchmarks, dict)
        assert isinstance(monitor.has_gpu, bool)

    def test_start_and_end_inference(self, monitor: ModelPerformanceMonitor) -> None:
        """Inference tracking records accurate metrics."""
        context = monitor.start_inference("test-model")

        assert "model_id" in context
        assert context["model_id"] == "test-model"
        assert "start_time" in context
        assert "start_memory" in context

        time.sleep(0.1)

        metrics = monitor.end_inference(
            context,
            tokens_generated=50,
            batch_size=1,
            sequence_length=256
        )

        assert metrics.model_id == "test-model"
        assert metrics.inference_time >= 0.1
        assert metrics.tokens_generated == 50
        assert metrics.tokens_per_second > 0
        assert metrics.batch_size == 1
        assert metrics.sequence_length == 256

    def test_inference_tracking_calculates_tokens_per_second(self, monitor: ModelPerformanceMonitor) -> None:
        """Tokens per second calculation is accurate."""
        context = monitor.start_inference("speed-test-model")
        time.sleep(0.2)

        metrics = monitor.end_inference(context, tokens_generated=100)

        expected_tps = 100 / metrics.inference_time
        assert abs(metrics.tokens_per_second - expected_tps) < 1.0

    def test_metrics_added_to_history(self, monitor: ModelPerformanceMonitor) -> None:
        """Metrics are added to model history."""
        context = monitor.start_inference("history-test-model")
        monitor.end_inference(context, tokens_generated=25)

        assert "history-test-model" in monitor.metrics_history
        assert len(monitor.metrics_history["history-test-model"]) == 1

    def test_multiple_inferences_tracked(self, monitor: ModelPerformanceMonitor) -> None:
        """Multiple inferences are tracked correctly."""
        model_id = "multi-inference-model"

        for i in range(5):
            context = monitor.start_inference(model_id)
            time.sleep(0.05)
            monitor.end_inference(context, tokens_generated=10 * (i + 1))

        assert model_id in monitor.metrics_history
        assert len(monitor.metrics_history[model_id]) == 5

        metrics_list = list(monitor.metrics_history[model_id])
        assert metrics_list[0].tokens_generated == 10
        assert metrics_list[4].tokens_generated == 50

    def test_history_size_limit_enforced(self, temp_save_dir: Path) -> None:
        """Metrics history respects maximum size limit."""
        monitor = ModelPerformanceMonitor(history_size=10, save_dir=str(temp_save_dir))
        model_id = "limited-history-model"

        for _ in range(15):
            context = monitor.start_inference(model_id)
            monitor.end_inference(context, tokens_generated=10)

        assert len(monitor.metrics_history[model_id]) == 10

    def test_benchmark_updated_after_inference(self, monitor: ModelPerformanceMonitor) -> None:
        """Benchmark data is updated after inferences."""
        model_id = "benchmark-test-model"

        for _ in range(3):
            context = monitor.start_inference(model_id)
            time.sleep(0.05)
            monitor.end_inference(context, tokens_generated=20)

        assert model_id in monitor.benchmarks
        benchmark = monitor.benchmarks[model_id]

        assert benchmark.total_inferences >= 3
        assert benchmark.total_tokens >= 60
        assert benchmark.avg_tokens_per_second > 0
        assert benchmark.avg_inference_time > 0

    def test_benchmark_calculates_percentiles(self, monitor: ModelPerformanceMonitor) -> None:
        """Benchmark calculates latency percentiles."""
        model_id = "percentile-test-model"

        for _ in range(20):
            context = monitor.start_inference(model_id)
            time.sleep(0.05)
            monitor.end_inference(context, tokens_generated=10)

        benchmark = monitor.benchmarks[model_id]

        assert benchmark.p50_latency > 0
        assert benchmark.p95_latency > 0
        assert benchmark.p99_latency > 0
        assert benchmark.p50_latency <= benchmark.p95_latency <= benchmark.p99_latency

    def test_error_tracking(self, monitor: ModelPerformanceMonitor) -> None:
        """Failed inferences are tracked with error information."""
        context = monitor.start_inference("error-test-model")

        metrics = monitor.end_inference(
            context,
            tokens_generated=0,
            error="Test error message"
        )

        assert metrics.error == "Test error message"
        assert "error-test-model" in monitor.metrics_history

    def test_error_rate_calculation(self, monitor: ModelPerformanceMonitor) -> None:
        """Error rate is calculated correctly."""
        model_id = "error-rate-model"

        for i in range(10):
            context = monitor.start_inference(model_id)
            error = "Error" if i % 3 == 0 else None
            monitor.end_inference(context, tokens_generated=10 if not error else 0, error=error)

        benchmark = monitor.benchmarks[model_id]
        expected_error_rate = 4 / 10

        assert abs(benchmark.error_rate - expected_error_rate) < 0.01

    def test_get_stats_returns_comprehensive_data(self, monitor: ModelPerformanceMonitor) -> None:
        """get_stats returns comprehensive performance statistics."""
        model_id = "stats-test-model"

        for _ in range(5):
            context = monitor.start_inference(model_id)
            time.sleep(0.05)
            monitor.end_inference(context, tokens_generated=15)

        stats = monitor.get_stats(model_id)

        assert stats["model_name"] == model_id
        assert stats["status"] == "active"
        assert stats["total_inferences"] == 5
        assert "performance" in stats
        assert "resource_usage" in stats
        assert "latest" in stats
        assert stats["performance"]["avg_tokens_per_second"] > 0

    def test_get_stats_no_data(self, monitor: ModelPerformanceMonitor) -> None:
        """get_stats handles missing model data."""
        stats = monitor.get_stats("nonexistent-model")

        assert stats["status"] == "no_data"
        assert stats["total_inferences"] == 0

    def test_get_metrics_summary(self, monitor: ModelPerformanceMonitor) -> None:
        """get_metrics_summary provides recent performance data."""
        model_id = "summary-test-model"

        for _ in range(3):
            context = monitor.start_inference(model_id)
            time.sleep(0.05)
            monitor.end_inference(context, tokens_generated=20)

        summary = monitor.get_metrics_summary(model_id)

        assert summary["model_id"] == model_id
        assert summary["total_inferences"] == 3
        assert "recent_performance" in summary
        assert summary["recent_performance"]["avg_tokens_per_second"] > 0

    def test_compare_models(self, monitor: ModelPerformanceMonitor) -> None:
        """Model comparison identifies performance differences."""
        for _ in range(3):
            ctx = monitor.start_inference("fast-model")
            time.sleep(0.05)
            monitor.end_inference(ctx, tokens_generated=100)

        for _ in range(3):
            ctx = monitor.start_inference("slow-model")
            time.sleep(0.1)
            monitor.end_inference(ctx, tokens_generated=50)

        comparison = monitor.compare_models(
            ["fast-model", "slow-model"],
            metric="tokens_per_second"
        )

        assert comparison["metric"] == "tokens_per_second"
        assert "fast-model" in comparison["models"]
        assert "slow-model" in comparison["models"]
        assert "best_model" in comparison

    def test_compare_models_latency_metric(self, monitor: ModelPerformanceMonitor) -> None:
        """Model comparison works with latency metric (lower is better)."""
        for _ in range(3):
            ctx = monitor.start_inference("low-latency-model")
            time.sleep(0.05)
            monitor.end_inference(ctx, tokens_generated=50)

        for _ in range(3):
            ctx = monitor.start_inference("high-latency-model")
            time.sleep(0.15)
            monitor.end_inference(ctx, tokens_generated=50)

        comparison = monitor.compare_models(
            ["low-latency-model", "high-latency-model"],
            metric="latency"
        )

        assert comparison["best_model"] == "low-latency-model"

    def test_save_and_load_benchmarks(self, monitor: ModelPerformanceMonitor) -> None:
        """Benchmarks are saved and loaded correctly."""
        model_id = "persistent-model"

        for _ in range(5):
            context = monitor.start_inference(model_id)
            monitor.end_inference(context, tokens_generated=25)

        monitor._save_benchmarks()

        benchmark_file = monitor.save_dir / "benchmarks.json"
        assert benchmark_file.exists()

        new_monitor = ModelPerformanceMonitor(save_dir=str(monitor.save_dir))

        assert model_id in new_monitor.benchmarks
        original = monitor.benchmarks[model_id]
        loaded = new_monitor.benchmarks[model_id]

        assert loaded.total_inferences == original.total_inferences
        assert loaded.total_tokens == original.total_tokens

    def test_export_metrics_json(self, monitor: ModelPerformanceMonitor) -> None:
        """Metrics can be exported to JSON format."""
        model_id = "export-test-model"

        for _ in range(3):
            context = monitor.start_inference(model_id)
            monitor.end_inference(context, tokens_generated=30)

        export_path = monitor.export_metrics(model_id=model_id, format="json")

        assert export_path is not None
        assert export_path.exists()
        assert export_path.suffix == ".json"

        with open(export_path) as f:
            data = json.load(f)

        assert model_id in data
        assert len(data[model_id]) == 3

    def test_export_metrics_csv(self, monitor: ModelPerformanceMonitor) -> None:
        """Metrics can be exported to CSV format."""
        model_id = "csv-export-model"

        for _ in range(2):
            context = monitor.start_inference(model_id)
            monitor.end_inference(context, tokens_generated=15)

        export_path = monitor.export_metrics(model_id=model_id, format="csv")

        assert export_path is not None
        assert export_path.exists()
        assert export_path.suffix == ".csv"

        content = export_path.read_text()
        assert "model_id" in content
        assert "tokens_generated" in content

    def test_export_all_metrics(self, monitor: ModelPerformanceMonitor) -> None:
        """Exporting without model_id exports all models."""
        for _ in range(2):
            ctx = monitor.start_inference("model-a")
            monitor.end_inference(ctx, tokens_generated=10)

        for _ in range(2):
            ctx = monitor.start_inference("model-b")
            monitor.end_inference(ctx, tokens_generated=20)

        export_path = monitor.export_metrics(format="json")

        assert export_path is not None

        with open(export_path) as f:
            data = json.load(f)

        assert "model-a" in data
        assert "model-b" in data

    def test_clear_metrics_specific_model(self, monitor: ModelPerformanceMonitor) -> None:
        """Clearing metrics for specific model removes only that model."""
        ctx1 = monitor.start_inference("model-1")
        monitor.end_inference(ctx1, tokens_generated=10)

        ctx2 = monitor.start_inference("model-2")
        monitor.end_inference(ctx2, tokens_generated=20)

        monitor.clear_metrics("model-1")

        assert "model-1" not in monitor.metrics_history
        assert "model-2" in monitor.metrics_history

    def test_clear_all_metrics(self, monitor: ModelPerformanceMonitor) -> None:
        """Clearing without model_id removes all metrics."""
        for _ in range(2):
            ctx = monitor.start_inference("test-model")
            monitor.end_inference(ctx, tokens_generated=10)

        monitor.clear_metrics()

        assert len(monitor.metrics_history) == 0
        assert len(monitor.benchmarks) == 0


class TestGlobalPerformanceMonitor:
    """Test global performance monitor singleton."""

    def test_get_performance_monitor_singleton(self) -> None:
        """Global performance monitor returns same instance."""
        monitor1 = get_performance_monitor()
        monitor2 = get_performance_monitor()

        assert monitor1 is monitor2
        assert isinstance(monitor1, ModelPerformanceMonitor)

    def test_get_performance_monitor_initialization(self) -> None:
        """Global performance monitor is properly initialized."""
        monitor = get_performance_monitor()

        assert monitor.save_dir is not None
        assert monitor.save_dir.exists()
        assert isinstance(monitor.metrics_history, dict)


class TestPerformanceMonitorEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def monitor(self) -> Generator[ModelPerformanceMonitor, None, None]:
        """Create monitor for edge case testing."""
        temp_dir = tempfile.mkdtemp(prefix="perf_edge_")
        monitor = ModelPerformanceMonitor(save_dir=temp_dir)
        yield monitor
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_zero_tokens_generated(self, monitor: ModelPerformanceMonitor) -> None:
        """Metrics handle zero tokens generated."""
        context = monitor.start_inference("zero-tokens-model")
        metrics = monitor.end_inference(context, tokens_generated=0)

        assert metrics.tokens_generated == 0
        assert metrics.tokens_per_second == 0.0

    def test_very_fast_inference(self, monitor: ModelPerformanceMonitor) -> None:
        """Metrics handle very fast inferences."""
        context = monitor.start_inference("instant-model")
        metrics = monitor.end_inference(context, tokens_generated=1000)

        assert metrics.inference_time >= 0
        assert metrics.tokens_per_second >= 0

    def test_get_metrics_summary_no_data(self, monitor: ModelPerformanceMonitor) -> None:
        """Metrics summary handles missing model."""
        summary = monitor.get_metrics_summary("nonexistent-model")

        assert "error" in summary

    def test_compare_models_empty_list(self, monitor: ModelPerformanceMonitor) -> None:
        """Model comparison handles empty model list."""
        comparison = monitor.compare_models([], metric="tokens_per_second")

        assert comparison["metric"] == "tokens_per_second"
        assert len(comparison["models"]) == 0

    def test_load_corrupted_benchmarks(self, monitor: ModelPerformanceMonitor) -> None:
        """Loading corrupted benchmark file handles gracefully."""
        benchmark_file = monitor.save_dir / "benchmarks.json"
        benchmark_file.write_text("{ invalid json }")

        new_monitor = ModelPerformanceMonitor(save_dir=str(monitor.save_dir))

        assert isinstance(new_monitor.benchmarks, dict)

    def test_device_detection(self, monitor: ModelPerformanceMonitor) -> None:
        """Device detection works correctly."""
        context = monitor.start_inference("device-test-model")
        metrics = monitor.end_inference(context, tokens_generated=10)

        assert metrics.device in ["cpu", "cuda", "mps", "auto"]

    def test_quantization_tracking(self, monitor: ModelPerformanceMonitor) -> None:
        """Quantization information is tracked."""
        context = monitor.start_inference("quant-model")
        metrics = monitor.end_inference(
            context,
            tokens_generated=50,
            quantization="int4"
        )

        assert metrics.quantization == "int4"
