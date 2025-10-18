"""
Integration tests for GPU monitoring widgets.

This module contains comprehensive tests for the GPU status widget and system monitor widget
using REAL GPU APIs and hardware detection. Tests use actual nvidia-smi, WMI, and GPUtil
to validate production functionality.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import platform
import subprocess
import sys
from typing import Any

import pytest

from intellicrack.ui.widgets.gpu_status_widget import GPUMonitorWorker
from intellicrack.ui.widgets.system_monitor_widget import SystemMonitorWorker


def is_nvidia_available() -> bool:
    """Check if NVIDIA GPU and nvidia-smi are available."""
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=count", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        return result.returncode == 0 and int(result.stdout.strip()) > 0
    except (FileNotFoundError, subprocess.SubprocessError, ValueError):
        return False


def is_wmi_available() -> bool:
    """Check if WMI is available (Windows only)."""
    if platform.system() != "Windows":
        return False
    try:
        import wmi
        c = wmi.WMI()
        gpus = list(c.Win32_VideoController())
        return len(gpus) > 0
    except (ImportError, Exception):
        return False


def is_gputil_available() -> bool:
    """Check if GPUtil can detect GPUs."""
    try:
        import GPUtil
        gpus = GPUtil.getGPUs()
        return len(gpus) > 0
    except (ImportError, Exception):
        return False


class TestGPUMonitorWorkerIntegration:
    """Integration tests for GPUMonitorWorker with real GPU hardware."""

    @pytest.fixture
    def worker(self):
        """Create a GPUMonitorWorker instance."""
        return GPUMonitorWorker()

    @pytest.mark.skipif(not is_nvidia_available(), reason="NVIDIA GPU not available")
    def test_nvidia_gpu_real_detection(self, worker):
        """Test NVIDIA GPU detection with real nvidia-smi."""
        gpus = worker._get_nvidia_gpu_info()

        assert len(gpus) > 0, "Should detect at least one NVIDIA GPU"

        for gpu in gpus:
            assert gpu['vendor'] == 'NVIDIA'
            assert isinstance(gpu['index'], int)
            assert len(gpu['name']) > 0
            assert 0 <= gpu['temperature'] <= 150.0
            assert 0 <= gpu['utilization'] <= 100.0
            assert gpu['memory_used'] >= 0
            assert gpu['memory_total'] > 0
            assert gpu['memory_used'] <= gpu['memory_total']
            assert 0 <= gpu['power'] <= 1000.0

    @pytest.mark.skipif(not is_wmi_available(), reason="WMI/Windows GPU not available")
    def test_intel_gpu_real_detection(self, worker):
        """Test Intel GPU detection with real WMI on Windows."""
        gpus = worker._get_intel_arc_info()

        if len(gpus) > 0:
            for gpu in gpus:
                assert gpu['vendor'] == 'Intel'
                assert 'Intel' in gpu['name']
                assert 0 <= gpu['utilization'] <= 100.0
                assert 0 <= gpu['temperature'] <= 150.0
                assert gpu['memory_used'] >= 0
                assert gpu['memory_total'] > 0
                assert gpu['memory_used'] <= gpu['memory_total']
                assert 0 <= gpu['power'] <= 500.0

    @pytest.mark.skipif(not is_wmi_available(), reason="WMI/Windows GPU not available")
    def test_amd_gpu_real_detection(self, worker):
        """Test AMD GPU detection with real WMI on Windows."""
        gpus = worker._get_amd_gpu_info()

        if len(gpus) > 0:
            for gpu in gpus:
                assert gpu['vendor'] == 'AMD'
                assert any(x in gpu['name'] for x in ['AMD', 'Radeon', 'ATI'])
                assert 0 <= gpu['utilization'] <= 100.0
                assert 0 <= gpu['temperature'] <= 150.0
                assert gpu['memory_used'] >= 0
                assert gpu['memory_total'] > 0
                assert gpu['memory_used'] <= gpu['memory_total']
                assert 0 <= gpu['power'] <= 600.0

    def test_nvidia_gpu_not_available_graceful_failure(self, worker):
        """Test NVIDIA GPU detection gracefully handles absence of nvidia-smi."""
        if not is_nvidia_available():
            gpus = worker._get_nvidia_gpu_info()
            assert gpus == [], "Should return empty list when nvidia-smi not available"

    def test_intel_gpu_not_available_graceful_failure(self, worker):
        """Test Intel GPU detection gracefully handles WMI unavailability."""
        if not is_wmi_available():
            gpus = worker._get_intel_arc_info()
            assert gpus == [], "Should return empty list when WMI not available"

    def test_amd_gpu_not_available_graceful_failure(self, worker):
        """Test AMD GPU detection gracefully handles WMI unavailability."""
        if not is_wmi_available():
            gpus = worker._get_amd_gpu_info()
            assert gpus == [], "Should return empty list when WMI not available"

    def test_collect_gpu_data_real_platform(self, worker):
        """Test GPU data collection on real platform."""
        data = worker._collect_gpu_data()

        assert 'platform' in data
        assert data['platform'] == platform.system()
        assert 'gpus' in data
        assert isinstance(data['gpus'], list)
        assert 'error' in data

        if len(data['gpus']) > 0:
            assert data['error'] is None
            for gpu in data['gpus']:
                assert 'vendor' in gpu
                assert 'name' in gpu
                assert 'utilization' in gpu
                assert 'temperature' in gpu
                assert 'memory_used' in gpu
                assert 'memory_total' in gpu
                assert 'power' in gpu

    def test_nvidia_gpu_value_validation(self, worker):
        """Test NVIDIA GPU values are within realistic ranges."""
        if is_nvidia_available():
            gpus = worker._get_nvidia_gpu_info()

            for gpu in gpus:
                assert gpu['temperature'] >= 0 and gpu['temperature'] <= 150
                assert gpu['utilization'] >= 0 and gpu['utilization'] <= 100
                assert gpu['power'] >= 0 and gpu['power'] <= 1000
                assert gpu['memory_used'] >= 0
                assert gpu['memory_total'] > 0

    def test_intel_gpu_value_validation(self, worker):
        """Test Intel GPU values are within realistic ranges."""
        if is_wmi_available():
            gpus = worker._get_intel_arc_info()

            for gpu in gpus:
                assert gpu['temperature'] >= 0 and gpu['temperature'] <= 150
                assert gpu['utilization'] >= 0 and gpu['utilization'] <= 100
                assert gpu['power'] >= 0 and gpu['power'] <= 500
                assert gpu['memory_used'] >= 0
                assert gpu['memory_total'] > 0

    def test_amd_gpu_value_validation(self, worker):
        """Test AMD GPU values are within realistic ranges."""
        if is_wmi_available():
            gpus = worker._get_amd_gpu_info()

            for gpu in gpus:
                assert gpu['temperature'] >= 0 and gpu['temperature'] <= 150
                assert gpu['utilization'] >= 0 and gpu['utilization'] <= 100
                assert gpu['power'] >= 0 and gpu['power'] <= 600
                assert gpu['memory_used'] >= 0
                assert gpu['memory_total'] > 0


class TestSystemMonitorWorkerIntegration:
    """Integration tests for SystemMonitorWorker with real system metrics."""

    @pytest.fixture
    def worker(self):
        """Create a SystemMonitorWorker instance."""
        return SystemMonitorWorker()

    def test_collect_metrics_real_system(self, worker):
        """Test metrics collection with real system data."""
        metrics = worker._collect_metrics()

        assert metrics.timestamp > 0
        assert 0 <= metrics.cpu_percent <= 100
        assert len(metrics.cpu_per_core) > 0
        assert all(0 <= core <= 100 for core in metrics.cpu_per_core)
        assert 0 <= metrics.memory_percent <= 100
        assert metrics.memory_used_gb >= 0
        assert metrics.memory_total_gb > 0
        assert metrics.memory_used_gb <= metrics.memory_total_gb
        assert metrics.network_sent_mb >= 0
        assert metrics.network_recv_mb >= 0
        assert metrics.disk_read_mb >= 0
        assert metrics.disk_write_mb >= 0

    @pytest.mark.skipif(not is_gputil_available(), reason="GPU not available")
    def test_collect_metrics_with_real_gpu(self, worker):
        """Test metrics collection with real GPU data."""
        metrics = worker._collect_metrics()

        if metrics.gpu_percent is not None:
            assert 0 <= metrics.gpu_percent <= 100

        if metrics.gpu_memory_percent is not None:
            assert 0 <= metrics.gpu_memory_percent <= 100

        if metrics.gpu_temp is not None:
            assert 0 <= metrics.gpu_temp <= 150

    def test_collect_metrics_no_gpu_graceful(self, worker):
        """Test metrics collection gracefully handles no GPU."""
        metrics = worker._collect_metrics()

        if not is_gputil_available():
            assert metrics.gpu_percent is None
            assert metrics.gpu_memory_percent is None
            assert metrics.gpu_temp is None

    def test_collect_metrics_multiple_calls(self, worker):
        """Test multiple metrics collections work correctly."""
        metrics1 = worker._collect_metrics()
        metrics2 = worker._collect_metrics()

        assert metrics1.timestamp <= metrics2.timestamp
        assert metrics1.cpu_percent >= 0
        assert metrics2.cpu_percent >= 0

    def test_network_io_calculation(self, worker):
        """Test network I/O delta calculation."""
        metrics1 = worker._collect_metrics()

        import time
        time.sleep(0.1)

        metrics2 = worker._collect_metrics()

        assert metrics2.network_sent_mb >= 0
        assert metrics2.network_recv_mb >= 0

    def test_disk_io_calculation(self, worker):
        """Test disk I/O delta calculation."""
        metrics1 = worker._collect_metrics()

        import time
        time.sleep(0.1)

        metrics2 = worker._collect_metrics()

        assert metrics2.disk_read_mb >= 0
        assert metrics2.disk_write_mb >= 0

    def test_gpu_value_validation_real_data(self, worker):
        """Test GPU values from real GPUtil are validated."""
        metrics = worker._collect_metrics()

        if metrics.gpu_percent is not None:
            assert isinstance(metrics.gpu_percent, float)
            assert metrics.gpu_percent >= 0.0
            assert metrics.gpu_percent <= 100.0

        if metrics.gpu_memory_percent is not None:
            assert isinstance(metrics.gpu_memory_percent, float)
            assert metrics.gpu_memory_percent >= 0.0
            assert metrics.gpu_memory_percent <= 100.0

        if metrics.gpu_temp is not None:
            assert isinstance(metrics.gpu_temp, float)
            assert metrics.gpu_temp >= 0.0
            assert metrics.gpu_temp <= 150.0

    def test_metrics_consistency_over_time(self, worker):
        """Test metrics remain consistent over multiple collections."""
        import time

        samples = []
        for _ in range(5):
            metrics = worker._collect_metrics()
            samples.append(metrics)
            time.sleep(0.1)

        for metrics in samples:
            assert 0 <= metrics.cpu_percent <= 100
            assert 0 <= metrics.memory_percent <= 100
            assert metrics.memory_used_gb <= metrics.memory_total_gb

    def test_cpu_per_core_count_matches_system(self, worker):
        """Test CPU per-core count matches actual system CPU count."""
        import psutil

        metrics = worker._collect_metrics()
        system_cpu_count = psutil.cpu_count(logical=True)

        assert len(metrics.cpu_per_core) == system_cpu_count

    def test_memory_totals_match_system(self, worker):
        """Test memory totals match actual system memory."""
        import psutil

        metrics = worker._collect_metrics()
        system_memory = psutil.virtual_memory()
        system_total_gb = system_memory.total / (1024**3)

        assert abs(metrics.memory_total_gb - system_total_gb) < 0.1
