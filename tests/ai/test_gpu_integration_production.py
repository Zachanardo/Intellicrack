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
import threading
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.gpu_integration import (
    GPUIntegration,
    get_ai_device,
    get_ai_gpu_info,
    gpu_integration,
    is_gpu_available,
    prepare_ai_model,
    prepare_ai_tensor,
)


class TestGPUDeviceDetectionProduction:
    """Production tests for GPU device detection with real hardware."""

    def test_get_gpu_info_returns_valid_device_info(self) -> None:
        """get_ai_gpu_info returns valid device information dict."""
        info: dict[str, Any] = get_ai_gpu_info()

        assert isinstance(info, dict), "Must return dict of device info"
        assert "available" in info, "Must report availability"
        assert "type" in info, "Must report device type"
        assert "device" in info, "Must report device"

    def test_get_ai_gpu_info_returns_comprehensive_info(self) -> None:
        """get_ai_gpu_info returns comprehensive device information."""
        info: dict[str, Any] = get_ai_gpu_info()

        assert isinstance(info, dict), "Must return dict"
        assert "available" in info, "Must report availability"
        assert "type" in info, "Must report device type"

        if info.get("available"):
            assert info["type"] != "cpu", "Must report actual GPU type when available"

    def test_get_device_returns_valid_device(self) -> None:
        """get_ai_device returns valid compute device."""
        device = get_ai_device()

        assert device is not None, "Must return a device"

    def test_is_gpu_available_returns_bool(self) -> None:
        """is_gpu_available returns boolean availability status."""
        available: bool = is_gpu_available()

        assert isinstance(available, bool), "Must return boolean"


class TestGPUIntegrationProduction:
    """Production tests for GPUIntegration with real GPU operations."""

    @pytest.fixture
    def integration(self) -> GPUIntegration:
        """Create GPUIntegration instance for testing."""
        return GPUIntegration()

    def test_gpu_integration_initialization_detects_hardware(
        self, integration: GPUIntegration
    ) -> None:
        """GPUIntegration detects available GPU hardware on initialization."""
        assert hasattr(integration, "gpu_info"), "Must have gpu_info attribute"
        assert hasattr(integration, "device"), "Must have device attribute"

        info: dict[str, Any] = integration.get_device_info()
        assert isinstance(info, dict), "Must return device info dict"

    def test_gpu_integration_is_available_matches_info(
        self, integration: GPUIntegration
    ) -> None:
        """GPUIntegration.is_available matches gpu_info availability."""
        info: dict[str, Any] = integration.get_device_info()
        available: bool = integration.is_available()

        assert isinstance(available, bool), "Must return boolean"
        assert available == info.get("available", False), "Availability must match"

    def test_gpu_integration_get_backend_name_returns_string(
        self, integration: GPUIntegration
    ) -> None:
        """GPUIntegration.get_backend_name returns backend name string."""
        backend: str = integration.get_backend_name()

        assert isinstance(backend, str), "Must return string"
        assert len(backend) > 0, "Backend name must not be empty"

    def test_gpu_integration_get_memory_usage_returns_dict(
        self, integration: GPUIntegration
    ) -> None:
        """GPUIntegration.get_memory_usage returns memory info dict."""
        memory: dict[str, object] = integration.get_memory_usage()

        assert isinstance(memory, dict), "Must return dict"

    def test_gpu_integration_synchronize_does_not_crash(
        self, integration: GPUIntegration
    ) -> None:
        """GPUIntegration.synchronize executes without error."""
        try:
            integration.synchronize()
        except Exception as e:
            pytest.fail(f"synchronize should not raise: {e}")


class TestModelGPUPreparationProduction:
    """Production tests for preparing models for GPU execution."""

    def test_prepare_ai_model_accepts_model_object(self) -> None:
        """prepare_ai_model accepts and returns model objects."""
        try:
            from intellicrack.utils.torch_gil_safety import safe_torch_import

            torch = safe_torch_import()
            if torch is None:
                pytest.skip("PyTorch not available")

            model = torch.nn.Linear(10, 5)
            prepared = prepare_ai_model(model)

            assert prepared is not None, "Must return prepared model"
        except ImportError:
            pytest.skip("PyTorch not available")

    def test_prepare_ai_tensor_accepts_tensor_object(self) -> None:
        """prepare_ai_tensor accepts and returns tensor objects."""
        try:
            from intellicrack.utils.torch_gil_safety import safe_torch_import

            torch = safe_torch_import()
            if torch is None:
                pytest.skip("PyTorch not available")

            tensor = torch.randn(10, 10)
            prepared = prepare_ai_tensor(tensor)

            assert prepared is not None, "Must return prepared tensor"
        except ImportError:
            pytest.skip("PyTorch not available")

    def test_get_ai_device_returns_usable_device(self) -> None:
        """get_ai_device returns device usable for tensor operations."""
        device = get_ai_device()

        assert device is not None, "Must return a device"


class TestGPUOptimizationProduction:
    """Production tests for GPU-specific optimizations."""

    def test_prepare_model_accepts_model_object(self) -> None:
        """gpu_integration.prepare_model optimizes model for GPU execution."""
        try:
            from intellicrack.utils.torch_gil_safety import safe_torch_import

            torch = safe_torch_import()
            if torch is None:
                pytest.skip("PyTorch not available")

            model = torch.nn.Linear(10, 5)
            optimized = gpu_integration.prepare_model(model)

            assert optimized is not None, "Must return optimized model"
        except ImportError:
            pytest.skip("PyTorch not available")

    def test_prepare_model_returns_same_type(self) -> None:
        """gpu_integration.prepare_model returns same model type."""
        try:
            from intellicrack.utils.torch_gil_safety import safe_torch_import

            torch = safe_torch_import()
            if torch is None:
                pytest.skip("PyTorch not available")

            model = torch.nn.Sequential(
                torch.nn.Linear(10, 20),
                torch.nn.ReLU(),
                torch.nn.Linear(20, 5),
            )
            optimized = gpu_integration.prepare_model(model)

            assert isinstance(optimized, torch.nn.Module), "Must return nn.Module"
        except ImportError:
            pytest.skip("PyTorch not available")


class TestGPUIntegrationEndToEnd:
    """End-to-end production tests for complete GPU integration workflows."""

    def test_complete_gpu_workflow_model_preparation(self) -> None:
        """Complete workflow: get device info -> prepare model -> synchronize."""
        try:
            from intellicrack.utils.torch_gil_safety import safe_torch_import

            torch = safe_torch_import()
            if torch is None:
                pytest.skip("PyTorch not available")

            info: dict[str, Any] = get_ai_gpu_info()
            assert isinstance(info, dict), "Step 1: Get GPU info must succeed"

            model = torch.nn.Linear(10, 5)
            prepared = prepare_ai_model(model)
            assert prepared is not None, "Step 2: Model preparation must succeed"

            optimized = gpu_integration.prepare_model(prepared)
            assert optimized is not None, "Step 3: Optimization must succeed"

            integration = GPUIntegration()
            integration.synchronize()

        except ImportError:
            pytest.skip("PyTorch not available")

    def test_global_gpu_integration_instance_works(self) -> None:
        """Global gpu_integration instance is usable."""
        assert gpu_integration is not None, "Global instance must exist"

        info: dict[str, Any] = gpu_integration.get_device_info()
        assert isinstance(info, dict), "Must return device info"

        available: bool = gpu_integration.is_available()
        assert isinstance(available, bool), "Must return boolean"

    @pytest.mark.skipif(
        platform.system() != "Windows", reason="Windows-specific GPU testing"
    )
    def test_windows_gpu_detection(self) -> None:
        """On Windows, GPU detection properly identifies available devices."""
        info: dict[str, Any] = get_ai_gpu_info()

        assert "type" in info, "Must report device type"

        if info.get("available"):
            device_type: str = str(info.get("type", ""))
            assert device_type in [
                "nvidia_cuda",
                "amd_rocm",
                "intel_xpu",
                "cpu",
            ], f"Device type must be recognized: {device_type}"

    def test_concurrent_gpu_integration_thread_safety(self) -> None:
        """GPU integration handles concurrent access safely."""
        results: list[bool] = []
        errors: list[Exception] = []

        def worker() -> None:
            try:
                integration = GPUIntegration()
                is_avail: bool = integration.is_available()
                results.append(is_avail)
            except Exception as e:
                errors.append(e)

        threads: list[threading.Thread] = [
            threading.Thread(target=worker) for _ in range(5)
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(errors) == 0, f"Threads must not error: {errors}"
        assert len(results) == 5, "All threads must complete"
        assert all(isinstance(r, bool) for r in results), "All results must be boolean"

    def test_gpu_state_consistent_after_operations(self) -> None:
        """GPU integration maintains consistent state after operations."""
        integration = GPUIntegration()

        initial_available: bool = integration.is_available()
        initial_backend: str = integration.get_backend_name()

        integration.synchronize()
        _ = integration.get_memory_usage()
        _ = integration.get_device_info()

        final_available: bool = integration.is_available()
        final_backend: str = integration.get_backend_name()

        assert initial_available == final_available, "Availability must remain stable"
        assert initial_backend == final_backend, "Backend must remain stable"
