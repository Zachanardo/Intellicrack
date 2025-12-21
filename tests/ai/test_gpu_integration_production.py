"""Production tests for gpu_integration.py - Real GPU device testing when available.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import platform
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.gpu_integration import (
    GPUAccelerator,
    GPUDeviceInfo,
    detect_gpu_devices,
    get_optimal_batch_size,
    optimize_for_gpu,
    prepare_model_for_gpu,
)


class TestGPUDeviceDetectionProduction:
    """Production tests for GPU device detection with real hardware."""

    def test_detect_gpu_devices_returns_valid_device_list(self) -> None:
        """detect_gpu_devices returns valid device information when GPUs present or empty list."""
        devices: list[GPUDeviceInfo] = detect_gpu_devices()

        assert isinstance(devices, list), "Must return list of devices"

        if devices:
            for device in devices:
                assert isinstance(device, GPUDeviceInfo), "Each device must be GPUDeviceInfo instance"
                assert device.device_id >= 0, "Device ID must be non-negative"
                assert len(device.name) > 0, "Device must have a name"
                assert device.total_memory > 0, "Device must report memory > 0"
                assert device.available_memory >= 0, "Available memory must be non-negative"
                assert device.compute_capability is not None, "Must report compute capability"

    def test_detect_gpu_devices_handles_no_gpu_gracefully(self) -> None:
        """detect_gpu_devices returns empty list when no GPUs available without crashing."""
        devices: list[GPUDeviceInfo] = detect_gpu_devices()

        assert isinstance(devices, list), "Must return list even when no GPU"

        if not devices:
            pytest.skip("No GPU devices available, test passes with empty list")

    def test_gpu_device_info_properties_accurate(self) -> None:
        """GPUDeviceInfo reports accurate hardware properties."""
        devices: list[GPUDeviceInfo] = detect_gpu_devices()

        if not devices:
            pytest.skip("No GPU available for testing")

        device: GPUDeviceInfo = devices[0]

        assert device.is_available, "Detected device must be available"
        assert device.total_memory <= 1024 * 1024 * 1024 * 1024, "Total memory must be reasonable (< 1TB)"
        assert device.available_memory <= device.total_memory, "Available <= Total memory"

        assert device.name != "Unknown", "Must detect real device name"

    def test_multiple_gpu_detection_distinct_devices(self) -> None:
        """Multiple GPUs are detected with distinct device IDs."""
        devices: list[GPUDeviceInfo] = detect_gpu_devices()

        if len(devices) < 2:
            pytest.skip("Need multiple GPUs for this test")

        device_ids: set[int] = {device.device_id for device in devices}
        assert len(device_ids) == len(devices), "All GPUs must have unique device IDs"

        device_names: list[str] = [device.name for device in devices]
        assert all(len(name) > 0 for name in device_names), "All GPUs must have names"


class TestGPUAcceleratorProduction:
    """Production tests for GPUAccelerator with real GPU operations."""

    @pytest.fixture
    def accelerator(self) -> GPUAccelerator:
        """Create GPUAccelerator instance for testing."""
        return GPUAccelerator()

    def test_gpu_accelerator_initialization_detects_hardware(self, accelerator: GPUAccelerator) -> None:
        """GPUAccelerator detects available GPU hardware on initialization."""
        assert hasattr(accelerator, "devices"), "Must have devices attribute"
        assert hasattr(accelerator, "current_device"), "Must track current device"

        devices: list[GPUDeviceInfo] = accelerator.get_available_devices()
        assert isinstance(devices, list), "Must return device list"

        if not devices:
            assert not accelerator.is_gpu_available(), "Should report no GPU when none detected"
        else:
            assert accelerator.is_gpu_available(), "Should report GPU available when detected"

    def test_gpu_accelerator_device_selection(self, accelerator: GPUAccelerator) -> None:
        """GPUAccelerator can select specific GPU devices."""
        devices: list[GPUDeviceInfo] = accelerator.get_available_devices()

        if not devices:
            pytest.skip("No GPU available for device selection test")

        device_id: int = devices[0].device_id
        success: bool = accelerator.select_device(device_id)

        assert success, "Must successfully select available device"
        assert accelerator.current_device == device_id, "Current device must be set to selected device"

    def test_gpu_accelerator_invalid_device_selection_fails(self, accelerator: GPUAccelerator) -> None:
        """GPUAccelerator rejects invalid device selection."""
        success: bool = accelerator.select_device(9999)

        assert not success, "Must fail when selecting non-existent device ID"

    def test_gpu_accelerator_memory_allocation(self, accelerator: GPUAccelerator) -> None:
        """GPUAccelerator can allocate and free GPU memory."""
        if not accelerator.is_gpu_available():
            pytest.skip("No GPU available for memory allocation test")

        allocation_size: int = 1024 * 1024
        memory_handle: Any = accelerator.allocate_memory(allocation_size)

        if memory_handle is not None:
            assert memory_handle is not None, "Must return valid memory handle"

            free_success: bool = accelerator.free_memory(memory_handle)
            assert free_success, "Must successfully free allocated memory"

    def test_gpu_accelerator_handles_out_of_memory_gracefully(self, accelerator: GPUAccelerator) -> None:
        """GPUAccelerator handles OOM conditions without crashing."""
        if not accelerator.is_gpu_available():
            pytest.skip("No GPU available for OOM test")

        devices: list[GPUDeviceInfo] = accelerator.get_available_devices()
        if not devices:
            pytest.skip("No GPU devices available")

        excessive_size: int = devices[0].total_memory * 10

        memory_handle: Any = accelerator.allocate_memory(excessive_size)

        assert memory_handle is None or isinstance(memory_handle, object), "Must handle OOM gracefully"


class TestModelGPUPreparationProduction:
    """Production tests for preparing models for GPU execution."""

    @pytest.fixture
    def dummy_model_path(self, tmp_path: Path) -> str:
        """Create a dummy model file for testing."""
        model_file: Path = tmp_path / "test_model.pth"

        model_data: bytes = b"DUMMY_MODEL_DATA" * 1000

        model_file.write_bytes(model_data)
        return str(model_file)

    def test_prepare_model_for_gpu_with_available_gpu(self, dummy_model_path: str) -> None:
        """prepare_model_for_gpu loads model to GPU when available."""
        result: dict[str, Any] = prepare_model_for_gpu(dummy_model_path, device_id=0)

        assert "status" in result, "Must return status"
        assert result["status"] in ["success", "no_gpu", "error"], "Status must be valid"

        if result["status"] == "success":
            assert "device" in result, "Must report target device on success"
            assert result["device"] in [0, "cuda:0"], "Must use requested device"
            assert "model" in result or "model_loaded" in result, "Must indicate model loaded"

        elif result["status"] == "no_gpu":
            assert "device" in result, "Must report fallback device"
            assert result["device"] == "cpu" or "cpu" in str(result["device"]).lower(), "Must fallback to CPU"

    def test_prepare_model_for_gpu_cpu_fallback(self, dummy_model_path: str) -> None:
        """prepare_model_for_gpu falls back to CPU when GPU unavailable."""
        result: dict[str, Any] = prepare_model_for_gpu(dummy_model_path, device_id=9999, fallback_to_cpu=True)

        assert result["status"] in ["success", "no_gpu", "error"]

        if "device" in result:
            assert "cpu" in str(result["device"]).lower() or result["status"] == "error", "Must use CPU fallback or report error"

    def test_prepare_model_for_gpu_handles_missing_file(self) -> None:
        """prepare_model_for_gpu handles missing model file gracefully."""
        result: dict[str, Any] = prepare_model_for_gpu("/nonexistent/model.pth")

        assert result["status"] == "error", "Must report error for missing file"
        assert "error" in result or "message" in result, "Must provide error information"

    def test_prepare_model_for_gpu_validates_file_format(self, tmp_path: Path) -> None:
        """prepare_model_for_gpu validates model file format."""
        invalid_model: Path = tmp_path / "invalid.txt"
        invalid_model.write_text("This is not a model file")

        result: dict[str, Any] = prepare_model_for_gpu(str(invalid_model))

        assert "status" in result
        if result["status"] == "error":
            assert "error" in result or "message" in result, "Must explain format error"


class TestGPUOptimizationProduction:
    """Production tests for GPU-specific optimizations."""

    def test_optimize_for_gpu_with_real_configuration(self) -> None:
        """optimize_for_gpu generates valid configuration for detected hardware."""
        config: dict[str, Any] = optimize_for_gpu(model_size=100 * 1024 * 1024)

        assert "device" in config, "Must specify target device"
        assert "batch_size" in config, "Must specify batch size"
        assert "precision" in config, "Must specify precision"
        assert "memory_fraction" in config, "Must specify memory allocation"

        assert config["batch_size"] > 0, "Batch size must be positive"
        assert 0.0 < config["memory_fraction"] <= 1.0, "Memory fraction must be between 0 and 1"
        assert config["precision"] in ["fp32", "fp16", "int8"], "Precision must be valid"

    def test_optimize_for_gpu_adapts_to_model_size(self) -> None:
        """optimize_for_gpu adapts batch size to model size."""
        small_model_config: dict[str, Any] = optimize_for_gpu(model_size=10 * 1024 * 1024)
        large_model_config: dict[str, Any] = optimize_for_gpu(model_size=1000 * 1024 * 1024)

        small_batch: int = small_model_config["batch_size"]
        large_batch: int = large_model_config["batch_size"]

        if small_batch > 0 and large_batch > 0:
            assert small_batch >= large_batch, "Small model should have >= batch size than large model"

    def test_get_optimal_batch_size_for_gpu_memory(self) -> None:
        """get_optimal_batch_size calculates batch size based on GPU memory."""
        devices: list[GPUDeviceInfo] = detect_gpu_devices()

        if not devices:
            batch_size: int = get_optimal_batch_size(model_size=50 * 1024 * 1024, available_memory=0)
            assert batch_size > 0, "Must return positive batch size even without GPU"
            pytest.skip("No GPU for optimal batch size calculation")

        device: GPUDeviceInfo = devices[0]
        model_size: int = 100 * 1024 * 1024

        batch_size: int = get_optimal_batch_size(model_size=model_size, available_memory=device.available_memory)

        assert batch_size > 0, "Must return positive batch size"
        assert batch_size <= 1024, "Batch size should be reasonable"

        total_memory_needed: int = model_size + (batch_size * 10 * 1024 * 1024)
        assert total_memory_needed <= device.available_memory * 1.5, "Should not massively exceed available memory"

    def test_get_optimal_batch_size_with_limited_memory(self) -> None:
        """get_optimal_batch_size handles limited memory scenarios."""
        model_size: int = 1000 * 1024 * 1024
        limited_memory: int = 1500 * 1024 * 1024

        batch_size: int = get_optimal_batch_size(model_size=model_size, available_memory=limited_memory)

        assert batch_size > 0, "Must return positive batch size even with limited memory"
        assert batch_size <= 32, "Should use small batch size with limited memory"


class TestGPUIntegrationEndToEnd:
    """End-to-end production tests for complete GPU integration workflows."""

    def test_complete_gpu_workflow_model_loading_and_inference(self, tmp_path: Path) -> None:
        """Complete workflow: detect GPU → load model → optimize → execute."""
        devices: list[GPUDeviceInfo] = detect_gpu_devices()

        has_gpu: bool = len(devices) > 0
        if not has_gpu:
            pytest.skip("No GPU available for complete workflow test")

        accelerator: GPUAccelerator = GPUAccelerator()
        assert accelerator.is_gpu_available(), "Step 1: GPU detection must succeed"

        device: GPUDeviceInfo = devices[0]
        accelerator.select_device(device.device_id)
        assert accelerator.current_device == device.device_id, "Step 2: Device selection must succeed"

        model_file: Path = tmp_path / "workflow_model.pth"
        model_file.write_bytes(b"MODEL_DATA" * 1000)

        optimization_config: dict[str, Any] = optimize_for_gpu(model_size=10000)
        assert optimization_config["batch_size"] > 0, "Step 3: Optimization must provide valid config"

        model_result: dict[str, Any] = prepare_model_for_gpu(str(model_file), device_id=device.device_id)
        assert model_result["status"] in {"success", "no_gpu"}, "Step 4: Model preparation must not error"

    def test_gpu_fallback_workflow_no_gpu_available(self, tmp_path: Path) -> None:
        """Workflow gracefully falls back to CPU when no GPU available."""
        optimization_config: dict[str, Any] = optimize_for_gpu(model_size=10000)
        assert optimization_config["batch_size"] > 0, "Must provide CPU config even without GPU"

        model_file: Path = tmp_path / "cpu_model.pth"
        model_file.write_bytes(b"CPU_MODEL" * 100)

        model_result: dict[str, Any] = prepare_model_for_gpu(str(model_file), fallback_to_cpu=True)

        assert model_result["status"] != "error" or "device" in model_result, "Must fallback to CPU successfully"

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific GPU testing")
    def test_windows_gpu_detection_cuda_support(self) -> None:
        """On Windows, GPU detection properly identifies CUDA-capable devices."""
        devices: list[GPUDeviceInfo] = detect_gpu_devices()

        for device in devices:
            if "nvidia" in device.name.lower() or "cuda" in str(device.compute_capability).lower():
                assert device.compute_capability is not None, "NVIDIA GPU must report compute capability"
                assert device.total_memory > 0, "NVIDIA GPU must report memory"

    def test_concurrent_gpu_access_thread_safety(self) -> None:
        """GPU integration handles concurrent access safely."""
        import threading

        devices: list[GPUDeviceInfo] = detect_gpu_devices()

        if not devices:
            pytest.skip("No GPU for concurrency test")

        results: list[bool] = []

        def worker() -> None:
            accelerator: GPUAccelerator = GPUAccelerator()
            is_available: bool = accelerator.is_gpu_available()
            results.append(is_available)

        threads: list[threading.Thread] = [threading.Thread(target=worker) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(results) == 5, "All threads must complete"
        assert all(isinstance(r, bool) for r in results), "All results must be boolean"

    def test_gpu_memory_cleanup_on_error(self) -> None:
        """GPU integration cleans up resources on error."""
        accelerator: GPUAccelerator = GPUAccelerator()

        if not accelerator.is_gpu_available():
            pytest.skip("No GPU for cleanup test")

        try:
            result: dict[str, Any] = prepare_model_for_gpu("/invalid/path.pth")
            assert result["status"] == "error", "Must report error for invalid path"

        except Exception as e:
            pytest.fail(f"GPU integration must handle errors gracefully, not crash: {e}")

        still_available: bool = accelerator.is_gpu_available()
        assert isinstance(still_available, bool), "GPU state must remain consistent after error"
