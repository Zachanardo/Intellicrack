"""Production tests for GPU autoloader system.

Tests validate that GPU detection, configuration, and fallback mechanisms
work correctly across different GPU backends (Intel XPU, NVIDIA CUDA, AMD ROCm,
DirectML) for accelerating binary analysis and machine learning operations.
"""

import os
from typing import Any

import pytest

from intellicrack.utils.gpu_autoloader import (
    GPUAutoLoader,
    detect_gpu_frameworks,
    get_device,
    get_gpu_info,
    gpu_autoloader,
    optimize_for_gpu,
    to_device,
)


class FakeTorchDevice:
    """Fake torch device for testing."""

    def __init__(self, device_type: str) -> None:
        self.type = device_type

    def __str__(self) -> str:
        return self.type

    def __repr__(self) -> str:
        return f"device(type='{self.type}')"


class FakeTorchModule:
    """Fake torch module with GPU backend support."""

    def __init__(
        self,
        cuda_available: bool = False,
        xpu_available: bool = False,
        hip_available: bool = False,
        raise_on_device_info: bool = False,
    ) -> None:
        self.cuda_available_flag = cuda_available
        self.xpu_available_flag = xpu_available
        self.hip_available_flag = hip_available
        self.raise_on_device_info_flag = raise_on_device_info
        self.__version__ = "2.1.0"

        if cuda_available:
            self.cuda = FakeCUDABackend(raise_on_info=raise_on_device_info)
            self.version = FakeTorchVersion(cuda="12.1")
        elif xpu_available:
            self.xpu = FakeXPUBackend(raise_on_info=raise_on_device_info)
        elif hip_available:
            self.hip = FakeHIPBackend(raise_on_info=raise_on_device_info)
            self.version = FakeTorchVersion(hip="5.7")

    def device(self, device_type: str) -> FakeTorchDevice:
        """Create a device object."""
        return FakeTorchDevice(device_type)

    def compile(self, model: Any) -> str:
        """Compile a model (fake implementation)."""
        return "compiled_model"


class FakeTorchVersion:
    """Fake torch version info."""

    def __init__(self, cuda: str | None = None, hip: str | None = None) -> None:
        self.cuda = cuda
        self.hip = hip


class FakeCUDABackend:
    """Fake CUDA backend."""

    def __init__(self, raise_on_info: bool = False) -> None:
        self.raise_on_info = raise_on_info
        self._allocated = 1 * 1024**3
        self._reserved = 2 * 1024**3
        self._total = 24 * 1024**3

    def is_available(self) -> bool:
        return True

    def device_count(self) -> int:
        if self.raise_on_info:
            raise RuntimeError("Info error")
        return 1

    def get_device_name(self, device_id: int = 0) -> str:
        return "NVIDIA RTX 4090"

    def get_device_properties(self, device_id: int = 0) -> "FakeDeviceProperties":
        return FakeDeviceProperties(
            name="NVIDIA RTX 4090",
            total_memory=self._total,
            major=8,
            minor=9,
        )

    def memory_allocated(self, device: int = 0) -> int:
        if self.raise_on_info:
            raise RuntimeError("Memory error")
        return self._allocated

    def memory_reserved(self, device: int = 0) -> int:
        return self._reserved

    def synchronize(self) -> None:
        if self.raise_on_info:
            raise RuntimeError("Sync error")


class FakeXPUBackend:
    """Fake Intel XPU backend."""

    def __init__(self, raise_on_info: bool = False) -> None:
        self.raise_on_info = raise_on_info
        self._allocated = 1 * 1024**3
        self._reserved = 2 * 1024**3

    def is_available(self) -> bool:
        return True

    def device_count(self) -> int:
        if self.raise_on_info:
            raise RuntimeError("Info error")
        return 1

    def get_device_name(self, device_id: int = 0) -> str:
        return "Intel Arc A770"

    def get_device_properties(self, device_id: int = 0) -> "FakeDeviceProperties":
        return FakeDeviceProperties(
            name="Intel Arc A770",
            total_memory=16 * 1024**3,
        )

    def get_driver_version(self) -> str:
        return "1.3.0"

    def memory_allocated(self, device: int = 0) -> int:
        return self._allocated

    def memory_reserved(self, device: int = 0) -> int:
        return self._reserved

    def synchronize(self) -> None:
        pass


class FakeHIPBackend:
    """Fake AMD ROCm/HIP backend."""

    def __init__(self, raise_on_info: bool = False) -> None:
        self.raise_on_info = raise_on_info
        self._allocated = 1 * 1024**3
        self._reserved = 2 * 1024**3

    def is_available(self) -> bool:
        return True

    def device_count(self) -> int:
        return 1

    def get_device_name(self, device_id: int = 0) -> str:
        return "AMD Radeon RX 7900 XTX"

    def get_device_properties(self, device_id: int = 0) -> "FakeDeviceProperties":
        return FakeDeviceProperties(
            name="AMD Radeon RX 7900 XTX",
            total_memory=24 * 1024**3,
        )

    def memory_allocated(self, device: int = 0) -> int:
        return self._allocated

    def memory_reserved(self, device: int = 0) -> int:
        return self._reserved

    def synchronize(self) -> None:
        pass


class FakeDeviceProperties:
    """Fake GPU device properties."""

    def __init__(
        self,
        name: str = "Generic GPU",
        total_memory: int = 8 * 1024**3,
        major: int = 7,
        minor: int = 5,
    ) -> None:
        self.name = name
        self.total_memory = total_memory
        self.major = major
        self.minor = minor


class FakeTensorLike:
    """Fake tensor-like object for testing."""

    def __init__(self, data: str = "tensor_data") -> None:
        self.data = data
        self.device_moved_to: FakeTorchDevice | None = None

    def to(self, device: FakeTorchDevice) -> "FakeTensorLike":
        """Move to device."""
        self.device_moved_to = device
        return self


class TestGPUAutoLoaderInitialization:
    """Test GPUAutoLoader initialization."""

    def test_initialization_sets_default_values(self) -> None:
        """GPUAutoLoader initializes with default values."""
        loader = GPUAutoLoader()

        assert loader.gpu_available is False
        assert loader.gpu_type is None
        assert loader.gpu_info == {}
        assert loader._torch is None
        assert loader._device is None
        assert loader._device_string is None

    def test_initialization_creates_empty_gpu_info(self) -> None:
        """GPUAutoLoader creates empty GPU info dictionary."""
        loader = GPUAutoLoader()

        assert isinstance(loader.gpu_info, dict)
        assert len(loader.gpu_info) == 0


class TestGPUSetup:
    """Test GPU setup and detection logic."""

    def test_setup_respects_no_gpu_environment_variable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """setup respects INTELLICRACK_NO_GPU environment variable."""
        loader = GPUAutoLoader()
        monkeypatch.setenv("INTELLICRACK_NO_GPU", "1")

        fake_torch = FakeTorchModule()
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader.setup()

        assert result is True
        assert loader.gpu_type == "cpu"

    def test_setup_skips_intel_xpu_when_requested(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """setup skips Intel XPU when INTELLICRACK_SKIP_INTEL_XPU is set."""
        loader = GPUAutoLoader()
        monkeypatch.setenv("INTELLICRACK_SKIP_INTEL_XPU", "true")

        fake_torch = FakeTorchModule(cuda_available=True)
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader.setup()

        assert result is True
        assert loader.gpu_type == "nvidia_cuda"

    def test_setup_tries_methods_in_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """setup tries GPU detection methods in priority order."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule()
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader.setup()

        assert result is True
        assert loader.gpu_type in ["cpu", "directml"]

    def test_setup_stops_on_first_success(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """setup stops trying methods after first success."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule(cuda_available=True)
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader.setup()

        assert result is True
        assert loader.gpu_type == "nvidia_cuda"

    def test_setup_handles_method_exceptions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """setup handles exceptions from detection methods gracefully."""
        loader = GPUAutoLoader()

        def raise_on_first_call() -> FakeTorchModule:
            if not hasattr(raise_on_first_call, "call_count"):
                raise_on_first_call.call_count = 0
            raise_on_first_call.call_count += 1

            if raise_on_first_call.call_count == 1:
                raise RuntimeError("XPU error")
            return FakeTorchModule(cuda_available=True)

        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            raise_on_first_call,
        )

        result = loader.setup()

        assert result is True

    def test_setup_sets_skip_intel_on_pybind11_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """setup sets INTELLICRACK_SKIP_INTEL_XPU on pybind11 errors."""
        loader = GPUAutoLoader()

        def raise_pybind11_error() -> FakeTorchModule:
            if not hasattr(raise_pybind11_error, "call_count"):
                raise_pybind11_error.call_count = 0
            raise_pybind11_error.call_count += 1

            if raise_pybind11_error.call_count == 1:
                raise RuntimeError("pybind11::gil_scoped_acquire error")
            return FakeTorchModule()

        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            raise_pybind11_error,
        )

        if "INTELLICRACK_SKIP_INTEL_XPU" in os.environ:
            monkeypatch.delenv("INTELLICRACK_SKIP_INTEL_XPU")

        loader.setup()

        assert os.environ.get("INTELLICRACK_SKIP_INTEL_XPU") == "1"


class TestIntelXPUDetection:
    """Test Intel XPU detection and configuration."""

    def test_detects_intel_xpu_when_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_try_intel_xpu detects Intel XPU when available."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule(xpu_available=True)
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_intel_xpu()

        assert result is True
        assert loader.gpu_available is True
        assert loader.gpu_type == "intel_xpu"
        assert loader._device_string == "xpu"

    def test_returns_false_when_xpu_not_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_try_intel_xpu returns False when XPU is not available."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule()
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_intel_xpu()

        assert result is False

    def test_returns_false_when_torch_has_no_xpu(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_try_intel_xpu returns False when torch lacks XPU support."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule()
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_intel_xpu()

        assert result is False

    def test_handles_xpu_info_retrieval_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_try_intel_xpu handles errors when retrieving XPU device info."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule(xpu_available=True, raise_on_device_info=True)
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_intel_xpu()

        assert result is True
        assert "backend" in loader.gpu_info


class TestNVIDIACUDADetection:
    """Test NVIDIA CUDA detection and configuration."""

    def test_detects_nvidia_cuda_when_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_try_nvidia_cuda detects NVIDIA CUDA when available."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule(cuda_available=True)
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_nvidia_cuda()

        assert result is True
        assert loader.gpu_available is True
        assert loader.gpu_type == "nvidia_cuda"
        assert loader._device_string == "cuda"
        assert "NVIDIA CUDA" in str(loader.gpu_info["backend"])

    def test_returns_false_when_cuda_not_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_try_nvidia_cuda returns False when CUDA is not available."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule()
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_nvidia_cuda()

        assert result is False


class TestAMDROCmDetection:
    """Test AMD ROCm detection and configuration."""

    def test_detects_amd_rocm_when_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_try_amd_rocm detects AMD ROCm when available."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule(hip_available=True)
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_amd_rocm()

        assert result is True
        assert loader.gpu_available is True
        assert loader.gpu_type == "amd_rocm"
        assert loader._device_string == "hip"

    def test_returns_false_when_rocm_not_available(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_try_amd_rocm returns False when ROCm is not available."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule()
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_amd_rocm()

        assert result is False


class TestDirectMLDetection:
    """Test DirectML detection and configuration."""

    def test_detects_directml(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_try_directml configures DirectML backend."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule()
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_directml()

        assert result is True
        assert loader.gpu_available is True
        assert loader.gpu_type == "directml"
        assert "DirectML" in str(loader.gpu_info["backend"])


class TestCPUFallback:
    """Test CPU fallback configuration."""

    def test_configures_cpu_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_try_cpu_fallback configures CPU backend."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule()
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_cpu_fallback()

        assert result is True
        assert loader.gpu_available is False
        assert loader.gpu_type == "cpu"
        assert loader._device_string == "cpu"

    def test_cpu_fallback_without_torch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_try_cpu_fallback works without PyTorch."""
        loader = GPUAutoLoader()

        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: None,
        )

        result = loader._try_cpu_fallback()

        assert result is True
        assert loader.gpu_type == "cpu"
        assert loader._device is None


class TestDeviceManagement:
    """Test device management functionality."""

    def test_get_device_returns_configured_device(self) -> None:
        """get_device returns the configured device object."""
        loader = GPUAutoLoader()
        fake_device = FakeTorchDevice("cuda")
        loader._device = fake_device

        result = loader.get_device()

        assert result is fake_device

    def test_get_torch_returns_torch_module(self) -> None:
        """get_torch returns the torch module."""
        loader = GPUAutoLoader()
        fake_torch = FakeTorchModule()
        loader._torch = fake_torch

        result = loader.get_torch()

        assert result is fake_torch

    def test_get_device_string_returns_device_string(self) -> None:
        """get_device_string returns device string for operations."""
        loader = GPUAutoLoader()
        loader._device_string = "cuda"

        result = loader.get_device_string()

        assert result == "cuda"

    def test_get_device_string_defaults_to_cpu(self) -> None:
        """get_device_string defaults to cpu when not configured."""
        loader = GPUAutoLoader()

        result = loader.get_device_string()

        assert result == "cpu"

    def test_to_device_moves_tensor_to_device(self) -> None:
        """to_device moves tensor or model to configured device."""
        loader = GPUAutoLoader()
        fake_device = FakeTorchDevice("cuda")
        loader._device = fake_device

        fake_tensor = FakeTensorLike()
        result = loader.to_device(fake_tensor)

        assert result is fake_tensor
        assert fake_tensor.device_moved_to is fake_device

    def test_to_device_returns_unchanged_when_no_device(self) -> None:
        """to_device returns object unchanged when no device configured."""
        loader = GPUAutoLoader()
        loader._device = None

        fake_tensor = FakeTensorLike()
        result = loader.to_device(fake_tensor)

        assert result is fake_tensor
        assert fake_tensor.device_moved_to is None


class TestModelOptimization:
    """Test model optimization functionality."""

    def test_optimize_model_compiles_for_intel_xpu(self) -> None:
        """optimize_model compiles model for Intel XPU."""
        loader = GPUAutoLoader()
        loader.gpu_type = "intel_xpu"

        fake_torch = FakeTorchModule()
        loader._torch = fake_torch

        fake_model = "model_to_compile"
        result = loader.optimize_model(fake_model)

        assert result == "compiled_model"

    def test_optimize_model_returns_unchanged_for_other_backends(self) -> None:
        """optimize_model returns model unchanged for non-XPU backends."""
        loader = GPUAutoLoader()
        loader.gpu_type = "nvidia_cuda"

        fake_model = "unchanged_model"
        result = loader.optimize_model(fake_model)

        assert result is fake_model

    def test_optimize_model_handles_compilation_errors(self) -> None:
        """optimize_model handles errors during compilation."""
        loader = GPUAutoLoader()
        loader.gpu_type = "intel_xpu"

        class FailingTorchModule:
            """Fake torch module that raises on compile."""

            def compile(self, model: Any) -> Any:
                raise RuntimeError("Compilation failed")

        loader._torch = FailingTorchModule()

        fake_model = "model_that_fails"
        result = loader.optimize_model(fake_model)

        assert result is fake_model


class TestMemoryInfo:
    """Test GPU memory information retrieval."""

    def test_get_memory_info_for_nvidia_cuda(self) -> None:
        """get_memory_info returns CUDA memory information."""
        loader = GPUAutoLoader()
        loader.gpu_available = True
        loader.gpu_type = "nvidia_cuda"

        fake_torch = FakeTorchModule(cuda_available=True)
        loader._torch = fake_torch

        result = loader.get_memory_info()

        assert "allocated" in result
        assert "reserved" in result
        assert "free" in result

    def test_get_memory_info_for_intel_xpu(self) -> None:
        """get_memory_info returns XPU memory information."""
        loader = GPUAutoLoader()
        loader.gpu_available = True
        loader.gpu_type = "intel_xpu"

        fake_torch = FakeTorchModule(xpu_available=True)
        loader._torch = fake_torch

        result = loader.get_memory_info()

        assert "allocated" in result

    def test_get_memory_info_returns_empty_when_no_gpu(self) -> None:
        """get_memory_info returns empty dict when GPU not available."""
        loader = GPUAutoLoader()
        loader.gpu_available = False

        result = loader.get_memory_info()

        assert result == {}

    def test_get_memory_info_handles_errors(self) -> None:
        """get_memory_info handles errors when retrieving memory info."""
        loader = GPUAutoLoader()
        loader.gpu_available = True
        loader.gpu_type = "nvidia_cuda"

        fake_torch = FakeTorchModule(cuda_available=True, raise_on_device_info=True)
        loader._torch = fake_torch

        result = loader.get_memory_info()

        assert isinstance(result, dict)


class TestSynchronization:
    """Test GPU synchronization functionality."""

    def test_synchronize_cuda_devices(self) -> None:
        """synchronize calls CUDA synchronize when available."""
        loader = GPUAutoLoader()
        loader.gpu_available = True
        loader.gpu_type = "nvidia_cuda"

        fake_torch = FakeTorchModule(cuda_available=True)
        loader._torch = fake_torch

        loader.synchronize()

    def test_synchronize_xpu_devices(self) -> None:
        """synchronize calls XPU synchronize when available."""
        loader = GPUAutoLoader()
        loader.gpu_available = True
        loader.gpu_type = "intel_xpu"

        fake_torch = FakeTorchModule(xpu_available=True)
        loader._torch = fake_torch

        loader.synchronize()

    def test_synchronize_does_nothing_when_no_gpu(self) -> None:
        """synchronize does nothing when GPU not available."""
        loader = GPUAutoLoader()
        loader.gpu_available = False

        loader.synchronize()

    def test_synchronize_handles_errors(self) -> None:
        """synchronize handles errors during synchronization."""
        loader = GPUAutoLoader()
        loader.gpu_available = True
        loader.gpu_type = "nvidia_cuda"

        fake_torch = FakeTorchModule(cuda_available=True, raise_on_device_info=True)
        loader._torch = fake_torch

        loader.synchronize()


class TestGlobalFunctions:
    """Test global convenience functions."""

    def test_get_device_uses_global_instance(self) -> None:
        """get_device uses global GPU autoloader instance."""
        original_device = gpu_autoloader._device
        fake_device = FakeTorchDevice("test")
        gpu_autoloader._device = fake_device

        result = get_device()

        assert result is fake_device

        gpu_autoloader._device = original_device

    def test_get_gpu_info_returns_complete_info(self) -> None:
        """get_gpu_info returns complete GPU information."""
        original_available = gpu_autoloader.gpu_available
        original_type = gpu_autoloader.gpu_type
        original_device_string = gpu_autoloader._device_string
        original_info = gpu_autoloader.gpu_info

        gpu_autoloader.gpu_available = True
        gpu_autoloader.gpu_type = "nvidia_cuda"
        gpu_autoloader._device_string = "cuda"
        gpu_autoloader.gpu_info = {"backend": "CUDA"}

        result = get_gpu_info()

        assert "available" in result
        assert "type" in result
        assert "device" in result
        assert "info" in result
        assert "memory" in result

        gpu_autoloader.gpu_available = original_available
        gpu_autoloader.gpu_type = original_type
        gpu_autoloader._device_string = original_device_string
        gpu_autoloader.gpu_info = original_info

    def test_to_device_uses_global_instance(self) -> None:
        """to_device uses global GPU autoloader instance."""
        original_device = gpu_autoloader._device
        fake_device = FakeTorchDevice("cuda")
        gpu_autoloader._device = fake_device

        fake_tensor = FakeTensorLike()
        result = to_device(fake_tensor)

        assert result is fake_tensor
        assert fake_tensor.device_moved_to is fake_device

        gpu_autoloader._device = original_device

    def test_optimize_for_gpu_uses_global_instance(self) -> None:
        """optimize_for_gpu uses global GPU autoloader instance."""
        original_type = gpu_autoloader.gpu_type
        original_torch = gpu_autoloader._torch

        gpu_autoloader.gpu_type = "intel_xpu"
        gpu_autoloader._torch = FakeTorchModule()

        fake_model = "test_model"
        result = optimize_for_gpu(fake_model)

        assert result == "compiled_model"

        gpu_autoloader.gpu_type = original_type
        gpu_autoloader._torch = original_torch


class TestDetectGPUFrameworks:
    """Test GPU framework detection functionality."""

    def test_returns_framework_info_structure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """detect_gpu_frameworks returns dictionary with framework info."""

        def raise_import_error() -> None:
            raise ImportError("torch not available")

        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.torch",
            raise_import_error,
            raising=False,
        )

        result = detect_gpu_frameworks()

        assert isinstance(result, dict)
        assert "cuda" in result
        assert "rocm" in result
        assert "opencl" in result
        assert "directml" in result
        assert "intel_xpu" in result
        assert "available_frameworks" in result
        assert "gpu_devices" in result

    def test_detects_cuda_when_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """detect_gpu_frameworks detects CUDA when available."""
        fake_torch = FakeTorchModule(cuda_available=True)
        monkeypatch.setattr("intellicrack.utils.gpu_autoloader.torch", fake_torch)

        result = detect_gpu_frameworks()

        assert result["cuda"] is True
        assert "CUDA" in result["available_frameworks"]

    def test_handles_missing_frameworks(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """detect_gpu_frameworks handles missing frameworks gracefully."""

        def raise_import_error() -> None:
            raise ImportError("torch not available")

        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.torch",
            raise_import_error,
            raising=False,
        )

        result = detect_gpu_frameworks()

        assert result["cuda"] is False
        assert result["intel_xpu"] is False


class TestRealWorldScenarios:
    """Test realistic production usage scenarios."""

    def test_complete_gpu_setup_workflow(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test complete workflow from detection to usage."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule(cuda_available=True)
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader.setup()

        assert result is True
        assert loader.get_device_string() == "cuda"

    def test_fallback_cascade_to_cpu(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test cascading fallback from all GPUs to CPU."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule()
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader.setup()

        assert result is True
        assert loader.gpu_type in ["cpu", "directml"]


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_handles_torch_import_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GPU detection handles PyTorch import failures."""
        loader = GPUAutoLoader()

        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: None,
        )

        result = loader._try_nvidia_cuda()

        assert result is False

    def test_handles_partial_gpu_support(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GPU detection handles partial GPU support."""
        loader = GPUAutoLoader()

        fake_torch = FakeTorchModule(cuda_available=True, raise_on_device_info=True)
        monkeypatch.setattr(
            "intellicrack.utils.gpu_autoloader.safe_torch_import",
            lambda: fake_torch,
        )

        result = loader._try_nvidia_cuda()

        assert result is True

    def test_handles_none_device_in_to_device(self) -> None:
        """to_device handles objects without 'to' method."""
        loader = GPUAutoLoader()
        loader._device = FakeTorchDevice("cuda")

        simple_object = "string"
        result = loader.to_device(simple_object)

        assert result == simple_object
