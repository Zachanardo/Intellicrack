"""
Model Performance Monitor for Intellicrack

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from intellicrack.logger import logger

from ..utils.logger import get_logger

# Try to import GPU autoloader
GPU_AUTOLOADER_AVAILABLE = False
get_device = None
get_gpu_info = None
to_device = None
memory_allocated = None
memory_reserved = None
empty_cache = None
gpu_autoloader = None

try:
    from ..utils.gpu_autoloader import (
        empty_cache,
        get_device,
        get_gpu_info,
        gpu_autoloader,
        memory_allocated,
        memory_reserved,
        to_device,
    )
    GPU_AUTOLOADER_AVAILABLE = True
except ImportError:
    pass

# Optional imports
HAS_NUMPY = False
HAS_PSUTIL = False
HAS_TORCH = False
HAS_PYNVML = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError as e:
    logger.error("Import error in model_performance_monitor: %s", e)
    np = None

try:
    import psutil
    HAS_PSUTIL = True
except ImportError as e:
    logger.error("Import error in model_performance_monitor: %s", e)
    psutil = None

try:
    import torch
    HAS_TORCH = True
except ImportError as e:
    logger.error("Import error in model_performance_monitor: %s", e)
    torch = None

try:
    import pynvml
    HAS_PYNVML = True
except ImportError as e:
    logger.error("Import error in model_performance_monitor: %s", e)
    pynvml = None

logger = get_logger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics for a single inference."""
    model_id: str
    timestamp: datetime
    inference_time: float  # seconds
    tokens_generated: int
    tokens_per_second: float
    memory_used_mb: float
    gpu_memory_mb: float
    cpu_percent: float
    gpu_percent: float
    batch_size: int
    sequence_length: int
    quantization: Optional[str] = None
    device: str = "cpu"
    error: Optional[str] = None


@dataclass
class ModelBenchmark:
    """Benchmark results for a model."""
    model_id: str
    avg_tokens_per_second: float
    avg_inference_time: float
    avg_memory_mb: float
    p50_latency: float
    p95_latency: float
    p99_latency: float
    total_inferences: int
    total_tokens: int
    error_rate: float
    device: str
    quantization: Optional[str] = None
    benchmark_date: datetime = field(default_factory=datetime.now)


class ModelPerformanceMonitor:
    """Monitors and tracks model performance metrics."""

    def __init__(self, history_size: int = 1000, save_dir: Optional[str] = None):
        """Initialize the performance monitor.

        Args:
            history_size: Number of metrics to keep in memory
            save_dir: Directory to save metrics
        """
        self.history_size = history_size
        self.metrics_history: Dict[str, deque] = {}
        self.benchmarks: Dict[str, ModelBenchmark] = {}

        if save_dir is None:
            save_dir = Path.home() / ".intellicrack" / "performance_metrics"

        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)

        # Load saved benchmarks
        self._load_benchmarks()

        # GPU monitoring
        if GPU_AUTOLOADER_AVAILABLE:
            gpu_info = get_gpu_info()
            self.has_gpu = gpu_info['available']
            self.gpu_type = gpu_info.get('gpu_type', 'unknown')
            self.gpu_count = gpu_info.get('device_count', 0)
        else:
            self.has_gpu = HAS_TORCH and torch.cuda.is_available()
            self.gpu_type = 'nvidia_cuda' if self.has_gpu else 'cpu'
            self.gpu_count = torch.cuda.device_count() if self.has_gpu else 0

        if self.has_gpu and self.gpu_type == 'nvidia_cuda':
            try:
                if HAS_PYNVML and pynvml:
                    pynvml.nvmlInit()
                    self.has_nvidia_ml = True
                    self.gpu_count = pynvml.nvmlDeviceGetCount()
                else:
                    raise ImportError("pynvml not available")
            except (ImportError, OSError, Exception):
                self.has_nvidia_ml = False
        else:
            self.has_nvidia_ml = False

    def _load_benchmarks(self):
        """Load saved benchmark data."""
        benchmark_file = self.save_dir / "benchmarks.json"
        if benchmark_file.exists():
            try:
                with open(benchmark_file, 'r') as f:
                    data = json.load(f)
                    for model_id, bench_data in data.items():
                        self.benchmarks[model_id] = ModelBenchmark(
                            model_id=model_id,
                            avg_tokens_per_second=bench_data["avg_tokens_per_second"],
                            avg_inference_time=bench_data["avg_inference_time"],
                            avg_memory_mb=bench_data["avg_memory_mb"],
                            p50_latency=bench_data["p50_latency"],
                            p95_latency=bench_data["p95_latency"],
                            p99_latency=bench_data["p99_latency"],
                            total_inferences=bench_data["total_inferences"],
                            total_tokens=bench_data["total_tokens"],
                            error_rate=bench_data["error_rate"],
                            device=bench_data["device"],
                            quantization=bench_data.get("quantization"),
                            benchmark_date=datetime.fromisoformat(
                                bench_data["benchmark_date"])
                        )
            except Exception as e:
                logger.error(f"Failed to load benchmarks: {e}")

    def _save_benchmarks(self):
        """Save benchmark data."""
        benchmark_file = self.save_dir / "benchmarks.json"
        try:
            data = {}
            for model_id, benchmark in self.benchmarks.items():
                data[model_id] = {
                    "avg_tokens_per_second": benchmark.avg_tokens_per_second,
                    "avg_inference_time": benchmark.avg_inference_time,
                    "avg_memory_mb": benchmark.avg_memory_mb,
                    "p50_latency": benchmark.p50_latency,
                    "p95_latency": benchmark.p95_latency,
                    "p99_latency": benchmark.p99_latency,
                    "total_inferences": benchmark.total_inferences,
                    "total_tokens": benchmark.total_tokens,
                    "error_rate": benchmark.error_rate,
                    "device": benchmark.device,
                    "quantization": benchmark.quantization,
                    "benchmark_date": benchmark.benchmark_date.isoformat()
                }

            with open(benchmark_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save benchmarks: {e}")

    def start_inference(self, model_id: str) -> Dict[str, Any]:
        """Start tracking an inference.

        Args:
            model_id: Model identifier

        Returns:
            Context dictionary to pass to end_inference
        """
        context = {
            "model_id": model_id,
            "start_time": time.time(),
            "start_memory": self._get_memory_usage(),
            "start_cpu": psutil.cpu_percent(interval=0.1) if HAS_PSUTIL else 0.0
        }

        if self.has_gpu:
            context["start_gpu_memory"] = self._get_gpu_memory_usage()
            context["start_gpu_util"] = self._get_gpu_utilization()

        return context

    def end_inference(
        self,
        context: Dict[str, Any],
        tokens_generated: int,
        batch_size: int = 1,
        sequence_length: int = 0,
        error: Optional[str] = None,
        **kwargs
    ) -> PerformanceMetrics:
        """End tracking an inference and record metrics.

        Args:
            context: Context from start_inference
            tokens_generated: Number of tokens generated
            batch_size: Batch size used
            sequence_length: Input sequence length
            error: Error message if inference failed
            **kwargs: Additional metadata

        Returns:
            Performance metrics
        """
        end_time = time.time()
        inference_time = end_time - context["start_time"]

        # Calculate metrics
        tokens_per_second = tokens_generated / \
            inference_time if inference_time > 0 else 0

        # Memory usage
        end_memory = self._get_memory_usage()
        memory_used = end_memory - context["start_memory"]

        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1) if HAS_PSUTIL else 0.0

        # GPU metrics
        gpu_memory = 0
        gpu_percent = 0
        if self.has_gpu:
            end_gpu_memory = self._get_gpu_memory_usage()
            gpu_memory = end_gpu_memory - context.get("start_gpu_memory", 0)
            gpu_percent = self._get_gpu_utilization()

        # Detect device
        device = kwargs.get("device", "cpu")
        if device == "auto":
            if GPU_AUTOLOADER_AVAILABLE:
                device = get_device()
            elif self.has_gpu:
                device = "cuda"

        # Create metrics
        metrics = PerformanceMetrics(
            model_id=context["model_id"],
            timestamp=datetime.now(),
            inference_time=inference_time,
            tokens_generated=tokens_generated,
            tokens_per_second=tokens_per_second,
            memory_used_mb=memory_used,
            gpu_memory_mb=gpu_memory,
            cpu_percent=cpu_percent,
            gpu_percent=gpu_percent,
            batch_size=batch_size,
            sequence_length=sequence_length,
            quantization=kwargs.get("quantization"),
            device=device,
            error=error
        )

        # Add to history
        if context["model_id"] not in self.metrics_history:
            self.metrics_history[context["model_id"]
                                 ] = deque(maxlen=self.history_size)

        self.metrics_history[context["model_id"]].append(metrics)

        # Update benchmark
        self._update_benchmark(context["model_id"], metrics)

        return metrics

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        if HAS_PSUTIL:
            process = psutil.Process()
            return process.memory_info().rss / (1024 * 1024)
        else:
            return 0.0

    def _get_gpu_memory_usage(self) -> float:
        """Get GPU memory usage in MB."""
        if not self.has_gpu:
            return 0

        try:
            if self.has_nvidia_ml and HAS_PYNVML and pynvml:
                total_memory = 0
                for i in range(self.gpu_count):
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                    info = pynvml.nvmlDeviceGetMemoryInfo(handle)
                    total_memory += info.used / (1024 * 1024)
                return total_memory
            else:
                # Fallback to unified GPU system or PyTorch
                if GPU_AUTOLOADER_AVAILABLE and memory_allocated:
                    return memory_allocated() / (1024 * 1024)
                elif HAS_TORCH and torch.cuda.is_available():
                    return torch.cuda.memory_allocated() / (1024 * 1024)
                else:
                    return 0.0
        except (AttributeError, RuntimeError, OSError):
            return 0

    def _get_gpu_utilization(self) -> float:
        """Get GPU utilization percentage."""
        if not self.has_gpu:
            return 0

        try:
            if self.has_nvidia_ml and HAS_PYNVML and pynvml:
                total_util = 0
                for i in range(self.gpu_count):
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)
                    util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                    total_util += util.gpu
                return total_util / self.gpu_count
            else:
                # Estimate based on memory usage
                if GPU_AUTOLOADER_AVAILABLE and memory_allocated and memory_reserved:
                    used_mem = memory_allocated()
                    total_mem = memory_reserved()
                    return (used_mem / total_mem) * 100 if total_mem > 0 else 0
                elif HAS_TORCH and torch.cuda.is_available():
                    total_mem = sum(
                        torch.cuda.get_device_properties(i).total_memory
                        for i in range(torch.cuda.device_count())
                    )
                    used_mem = torch.cuda.memory_allocated()
                    return (used_mem / total_mem) * 100 if total_mem > 0 else 0
                else:
                    return 0.0
        except (RuntimeError, AttributeError):
            return 0

    def _update_benchmark(self, model_id: str, metrics: PerformanceMetrics):
        """Update benchmark data for a model."""
        history = list(self.metrics_history.get(model_id, []))
        if not history:
            return

        # Calculate statistics
        inference_times = [
            m.inference_time for m in history if m.error is None]
        tokens_per_second = [
            m.tokens_per_second for m in history if m.error is None]
        memory_usage = [m.memory_used_mb + m.gpu_memory_mb for m in history]

        if not inference_times:
            return

        # Calculate percentiles
        latencies = sorted(inference_times)
        p50_idx = int(len(latencies) * 0.5)
        p95_idx = int(len(latencies) * 0.95)
        p99_idx = int(len(latencies) * 0.99)

        # Error rate
        error_count = sum(1 for m in history if m.error is not None)
        error_rate = error_count / len(history) if history else 0

        # Create/update benchmark
        self.benchmarks[model_id] = ModelBenchmark(
            model_id=model_id,
            avg_tokens_per_second=(np.mean(tokens_per_second) if HAS_NUMPY and tokens_per_second else sum(
                tokens_per_second)/len(tokens_per_second)) if tokens_per_second else 0,
            avg_inference_time=(np.mean(inference_times) if HAS_NUMPY else sum(
                inference_times)/len(inference_times)) if inference_times else 0,
            avg_memory_mb=(np.mean(memory_usage) if HAS_NUMPY else sum(
                memory_usage)/len(memory_usage)) if memory_usage else 0,
            p50_latency=latencies[p50_idx] if p50_idx < len(latencies) else 0,
            p95_latency=latencies[p95_idx] if p95_idx < len(latencies) else 0,
            p99_latency=latencies[p99_idx] if p99_idx < len(latencies) else 0,
            total_inferences=len(history),
            total_tokens=sum(m.tokens_generated for m in history),
            error_rate=error_rate,
            device=metrics.device,
            quantization=metrics.quantization
        )

        # Save periodically
        if len(history) % 10 == 0:
            self._save_benchmarks()

    def get_metrics_summary(self, model_id: str) -> Dict[str, Any]:
        """Get summary metrics for a model.

        Args:
            model_id: Model identifier

        Returns:
            Summary dictionary
        """
        if model_id not in self.metrics_history:
            return {"error": "No metrics found for model"}

        history = list(self.metrics_history[model_id])
        benchmark = self.benchmarks.get(model_id)

        # Recent performance (last 10 inferences)
        recent = history[-10:] if len(history) >= 10 else history
        recent_tps = [m.tokens_per_second for m in recent if m.error is None]
        recent_latency = [m.inference_time for m in recent if m.error is None]

        summary = {
            "model_id": model_id,
            "total_inferences": len(history),
            "recent_performance": {
                "avg_tokens_per_second": (np.mean(recent_tps) if HAS_NUMPY else sum(recent_tps)/len(recent_tps)) if recent_tps else 0,
                "avg_latency": (np.mean(recent_latency) if HAS_NUMPY else sum(recent_latency)/len(recent_latency)) if recent_latency else 0,
                "min_latency": (np.min(recent_latency) if HAS_NUMPY else min(recent_latency)) if recent_latency else 0,
                "max_latency": (np.max(recent_latency) if HAS_NUMPY else max(recent_latency)) if recent_latency else 0
            }
        }

        if benchmark:
            summary["benchmark"] = {
                "avg_tokens_per_second": benchmark.avg_tokens_per_second,
                "avg_inference_time": benchmark.avg_inference_time,
                "avg_memory_mb": benchmark.avg_memory_mb,
                "p50_latency": benchmark.p50_latency,
                "p95_latency": benchmark.p95_latency,
                "p99_latency": benchmark.p99_latency,
                "error_rate": benchmark.error_rate,
                "device": benchmark.device,
                "quantization": benchmark.quantization
            }

        # Resource usage
        if history:
            latest = history[-1]
            summary["latest_metrics"] = {
                "timestamp": latest.timestamp.isoformat(),
                "inference_time": latest.inference_time,
                "tokens_per_second": latest.tokens_per_second,
                "memory_mb": latest.memory_used_mb + latest.gpu_memory_mb,
                "cpu_percent": latest.cpu_percent,
                "gpu_percent": latest.gpu_percent
            }

        return summary

    def compare_models(
        self,
        model_ids: List[str],
        metric: str = "tokens_per_second"
    ) -> Dict[str, Any]:
        """Compare performance across multiple models.

        Args:
            model_ids: List of model IDs to compare
            metric: Metric to compare

        Returns:
            Comparison results
        """
        comparison = {
            "metric": metric,
            "models": {}
        }

        for model_id in model_ids:
            if model_id in self.benchmarks:
                benchmark = self.benchmarks[model_id]

                if metric == "tokens_per_second":
                    value = benchmark.avg_tokens_per_second
                elif metric == "latency":
                    value = benchmark.avg_inference_time
                elif metric == "memory":
                    value = benchmark.avg_memory_mb
                elif metric == "p95_latency":
                    value = benchmark.p95_latency
                else:
                    value = None

                comparison["models"][model_id] = {
                    "value": value,
                    "device": benchmark.device,
                    "quantization": benchmark.quantization,
                    "total_inferences": benchmark.total_inferences
                }

        # Find best performer
        if comparison["models"]:
            if metric in ["latency", "memory", "p95_latency"]:
                # Lower is better
                best_model = min(
                    comparison["models"].items(),
                    key=lambda x: x[1]["value"] if x[1]["value"] is not None else float(
                        'inf')
                )
            else:
                # Higher is better
                best_model = max(
                    comparison["models"].items(),
                    key=lambda x: x[1]["value"] if x[1]["value"] is not None else -
                    float('inf')
                )

            comparison["best_model"] = best_model[0]
            comparison["best_value"] = best_model[1]["value"]

        return comparison

    def optimize_for_monitoring(self, model: Any) -> Any:
        """Optimize model for performance monitoring.

        Args:
            model: Model to optimize

        Returns:
            Optimized model
        """
        if GPU_AUTOLOADER_AVAILABLE:
            try:
                # Move to optimal device
                if to_device:
                    device = get_device()
                    model = to_device(model, device)
                    logger.debug(f"Moved model to {device} for monitoring")

                # Apply GPU optimizations
                if gpu_autoloader:
                    optimized = gpu_autoloader(model)
                    if optimized is not None:
                        model = optimized
                        logger.debug("Applied GPU optimizations for monitoring")
            except Exception as e:
                logger.debug(f"Could not optimize model for monitoring: {e}")

        return model

    def clear_gpu_cache(self):
        """Clear GPU memory cache."""
        if GPU_AUTOLOADER_AVAILABLE and empty_cache:
            try:
                empty_cache()
                logger.debug("Cleared GPU cache")
            except Exception as e:
                logger.debug(f"Could not clear GPU cache: {e}")
        elif HAS_TORCH and torch.cuda.is_available():
            torch.cuda.empty_cache()

    def export_metrics(
        self,
        model_id: Optional[str] = None,
        format: str = "json"
    ) -> Optional[Path]:
        """Export metrics data.

        Args:
            model_id: Specific model or None for all
            format: Export format ("json" or "csv")

        Returns:
            Path to exported file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format == "json":
            filename = f"metrics_{model_id or 'all'}_{timestamp}.json"
            filepath = self.save_dir / filename

            data = {}
            if model_id:
                if model_id in self.metrics_history:
                    data[model_id] = [
                        {
                            "timestamp": m.timestamp.isoformat(),
                            "inference_time": m.inference_time,
                            "tokens_generated": m.tokens_generated,
                            "tokens_per_second": m.tokens_per_second,
                            "memory_mb": m.memory_used_mb + m.gpu_memory_mb,
                            "device": m.device,
                            "quantization": m.quantization,
                            "error": m.error
                        }
                        for m in self.metrics_history[model_id]
                    ]
            else:
                for mid, history in self.metrics_history.items():
                    data[mid] = [
                        {
                            "timestamp": m.timestamp.isoformat(),
                            "inference_time": m.inference_time,
                            "tokens_generated": m.tokens_generated,
                            "tokens_per_second": m.tokens_per_second,
                            "memory_mb": m.memory_used_mb + m.gpu_memory_mb,
                            "device": m.device,
                            "quantization": m.quantization,
                            "error": m.error
                        }
                        for m in history
                    ]

            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)

            return filepath

        elif format == "csv":
            import csv

            filename = f"metrics_{model_id or 'all'}_{timestamp}.csv"
            filepath = self.save_dir / filename

            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "model_id", "timestamp", "inference_time", "tokens_generated",
                    "tokens_per_second", "memory_mb", "device", "quantization", "error"
                ])

                if model_id and model_id in self.metrics_history:
                    for m in self.metrics_history[model_id]:
                        writer.writerow([
                            model_id, m.timestamp.isoformat(), m.inference_time,
                            m.tokens_generated, m.tokens_per_second,
                            m.memory_used_mb + m.gpu_memory_mb, m.device,
                            m.quantization, m.error
                        ])
                else:
                    for mid, history in self.metrics_history.items():
                        for m in history:
                            writer.writerow([
                                mid, m.timestamp.isoformat(), m.inference_time,
                                m.tokens_generated, m.tokens_per_second,
                                m.memory_used_mb + m.gpu_memory_mb, m.device,
                                m.quantization, m.error
                            ])

            return filepath

        return None

    def clear_metrics(self, model_id: Optional[str] = None):
        """Clear metrics data.

        Args:
            model_id: Specific model or None for all
        """
        if model_id:
            if model_id in self.metrics_history:
                del self.metrics_history[model_id]
            if model_id in self.benchmarks:
                del self.benchmarks[model_id]
        else:
            self.metrics_history.clear()
            self.benchmarks.clear()

        self._save_benchmarks()


# Global instance
_PERFORMANCE_MONITOR = None


def get_performance_monitor() -> ModelPerformanceMonitor:
    """Get the global performance monitor."""
    global _PERFORMANCE_MONITOR
    if _PERFORMANCE_MONITOR is None:
        _PERFORMANCE_MONITOR = ModelPerformanceMonitor()
    return _PERFORMANCE_MONITOR
