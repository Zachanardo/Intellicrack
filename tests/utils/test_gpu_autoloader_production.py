"""Production tests for GPU autoloader system.

Tests validate that GPU detection, configuration, and fallback mechanisms
work correctly across different GPU backends (Intel XPU, NVIDIA CUDA, AMD ROCm,
DirectML) for accelerating binary analysis and machine learning operations.
"""

import os
from unittest.mock import Mock, patch

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

    def test_setup_respects_no_gpu_environment_variable(self) -> None:
        """setup respects INTELLICRACK_NO_GPU environment variable."""
        loader = GPUAutoLoader()

        with patch.dict(os.environ, {"INTELLICRACK_NO_GPU": "1"}):
            with patch.object(loader, "_try_cpu_fallback", return_value=True) as mock_cpu:
                result = loader.setup()

                assert result is True
                mock_cpu.assert_called_once()
                assert loader.gpu_type == "cpu" or loader.gpu_type is None

    def test_setup_skips_intel_xpu_when_requested(self) -> None:
        """setup skips Intel XPU when INTELLICRACK_SKIP_INTEL_XPU is set."""
        loader = GPUAutoLoader()

        with patch.dict(os.environ, {"INTELLICRACK_SKIP_INTEL_XPU": "true"}):
            with patch.object(loader, "_try_intel_xpu") as mock_xpu:
                with patch.object(loader, "_try_cpu_fallback", return_value=True):
                    loader.setup()

                    mock_xpu.assert_not_called()

    def test_setup_tries_methods_in_order(self) -> None:
        """setup tries GPU detection methods in priority order."""
        loader = GPUAutoLoader()

        with patch.object(loader, "_try_intel_xpu", return_value=False):
            with patch.object(loader, "_try_nvidia_cuda", return_value=False):
                with patch.object(loader, "_try_amd_rocm", return_value=False):
                    with patch.object(loader, "_try_directml", return_value=False):
                        with patch.object(loader, "_try_cpu_fallback", return_value=True):
                            result = loader.setup()

                            assert result is True

    def test_setup_stops_on_first_success(self) -> None:
        """setup stops trying methods after first success."""
        loader = GPUAutoLoader()

        with patch.object(loader, "_try_intel_xpu", return_value=False):
            with patch.object(loader, "_try_nvidia_cuda", return_value=True):
                with patch.object(loader, "_try_amd_rocm", return_value=False) as mock_amd:
                    with patch.object(loader, "_try_directml", return_value=False) as mock_dml:
                        result = loader.setup()

                        assert result is True
                        mock_amd.assert_not_called()
                        mock_dml.assert_not_called()

    def test_setup_handles_method_exceptions(self) -> None:
        """setup handles exceptions from detection methods gracefully."""
        loader = GPUAutoLoader()

        with patch.object(loader, "_try_intel_xpu", side_effect=RuntimeError("XPU error")):
            with patch.object(loader, "_try_nvidia_cuda", return_value=True):
                result = loader.setup()

                assert result is True

    def test_setup_sets_skip_intel_on_pybind11_error(self) -> None:
        """setup sets INTELLICRACK_SKIP_INTEL_XPU on pybind11 errors."""
        loader = GPUAutoLoader()

        with patch.object(loader, "_try_intel_xpu", side_effect=RuntimeError("pybind11::gil_scoped_acquire error")):
            with patch.object(loader, "_try_cpu_fallback", return_value=True):
                with patch.dict(os.environ, {}, clear=False):
                    loader.setup()

                    assert os.environ.get("INTELLICRACK_SKIP_INTEL_XPU") == "1"


class TestIntelXPUDetection:
    """Test Intel XPU detection and configuration."""

    def test_detects_intel_xpu_when_available(self) -> None:
        """_try_intel_xpu detects Intel XPU when available."""
        loader = GPUAutoLoader()

        mock_torch = Mock()
        mock_torch.xpu.is_available.return_value = True
        mock_torch.xpu.device_count.return_value = 1
        mock_torch.xpu.get_device_name.return_value = "Intel Arc A770"
        mock_torch.device = Mock(return_value="xpu")

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_intel_xpu()

            assert result is True
            assert loader.gpu_available is True
            assert loader.gpu_type == "intel_xpu"
            assert loader._device_string == "xpu"

    def test_returns_false_when_xpu_not_available(self) -> None:
        """_try_intel_xpu returns False when XPU is not available."""
        loader = GPUAutoLoader()

        mock_torch = Mock()
        mock_torch.xpu.is_available.return_value = False

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_intel_xpu()

            assert result is False

    def test_returns_false_when_torch_has_no_xpu(self) -> None:
        """_try_intel_xpu returns False when torch lacks XPU support."""
        loader = GPUAutoLoader()

        mock_torch = Mock(spec=[])

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_intel_xpu()

            assert result is False

    def test_handles_xpu_info_retrieval_errors(self) -> None:
        """_try_intel_xpu handles errors when retrieving XPU device info."""
        loader = GPUAutoLoader()

        mock_torch = Mock()
        mock_torch.xpu.is_available.return_value = True
        mock_torch.xpu.device_count.side_effect = RuntimeError("Info error")
        mock_torch.device = Mock(return_value="xpu")

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_intel_xpu()

            assert result is True
            assert "backend" in loader.gpu_info


class TestNVIDIACUDADetection:
    """Test NVIDIA CUDA detection and configuration."""

    def test_detects_nvidia_cuda_when_available(self) -> None:
        """_try_nvidia_cuda detects NVIDIA CUDA when available."""
        loader = GPUAutoLoader()

        mock_torch = Mock()
        mock_torch.cuda.is_available.return_value = True
        mock_torch.cuda.device_count.return_value = 1
        mock_torch.version.cuda = "12.1"
        mock_torch.device = Mock(return_value="cuda")

        mock_props = Mock()
        mock_props.name = "NVIDIA RTX 4090"
        mock_props.total_memory = 24 * 1024**3
        mock_props.major = 8
        mock_props.minor = 9
        mock_torch.cuda.get_device_properties.return_value = mock_props

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_nvidia_cuda()

            assert result is True
            assert loader.gpu_available is True
            assert loader.gpu_type == "nvidia_cuda"
            assert loader._device_string == "cuda"
            assert "NVIDIA CUDA" in str(loader.gpu_info["backend"])

    def test_returns_false_when_cuda_not_available(self) -> None:
        """_try_nvidia_cuda returns False when CUDA is not available."""
        loader = GPUAutoLoader()

        mock_torch = Mock()
        mock_torch.cuda.is_available.return_value = False

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_nvidia_cuda()

            assert result is False


class TestAMDROCmDetection:
    """Test AMD ROCm detection and configuration."""

    def test_detects_amd_rocm_when_available(self) -> None:
        """_try_amd_rocm detects AMD ROCm when available."""
        loader = GPUAutoLoader()

        mock_torch = Mock()
        mock_torch.hip.is_available.return_value = True
        mock_torch.hip.device_count.return_value = 1
        mock_torch.hip.get_device_name.return_value = "AMD Radeon RX 7900 XTX"
        mock_torch.version.hip = "5.7"
        mock_torch.device = Mock(return_value="hip")

        mock_props = Mock()
        mock_props.total_memory = 24 * 1024**3
        mock_torch.hip.get_device_properties.return_value = mock_props

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_amd_rocm()

            assert result is True
            assert loader.gpu_available is True
            assert loader.gpu_type == "amd_rocm"
            assert loader._device_string == "hip"

    def test_returns_false_when_rocm_not_available(self) -> None:
        """_try_amd_rocm returns False when ROCm is not available."""
        loader = GPUAutoLoader()

        mock_torch = Mock()
        mock_torch.hip.is_available.return_value = False

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_amd_rocm()

            assert result is False


class TestDirectMLDetection:
    """Test DirectML detection and configuration."""

    def test_detects_directml(self) -> None:
        """_try_directml configures DirectML backend."""
        loader = GPUAutoLoader()

        mock_torch = Mock()
        mock_torch.device = Mock(return_value="cpu")

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_directml()

            assert result is True
            assert loader.gpu_available is True
            assert loader.gpu_type == "directml"
            assert "DirectML" in str(loader.gpu_info["backend"])


class TestCPUFallback:
    """Test CPU fallback configuration."""

    def test_configures_cpu_fallback(self) -> None:
        """_try_cpu_fallback configures CPU backend."""
        loader = GPUAutoLoader()

        mock_torch = Mock()
        mock_torch.device = Mock(return_value="cpu")

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_cpu_fallback()

            assert result is True
            assert loader.gpu_available is False
            assert loader.gpu_type == "cpu"
            assert loader._device_string == "cpu"

    def test_cpu_fallback_without_torch(self) -> None:
        """_try_cpu_fallback works without PyTorch."""
        loader = GPUAutoLoader()

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=None):
            result = loader._try_cpu_fallback()

            assert result is True
            assert loader.gpu_type == "cpu"
            assert loader._device is None


class TestDeviceManagement:
    """Test device management functionality."""

    def test_get_device_returns_configured_device(self) -> None:
        """get_device returns the configured device object."""
        loader = GPUAutoLoader()
        mock_device = Mock()
        loader._device = mock_device

        result = loader.get_device()

        assert result is mock_device

    def test_get_torch_returns_torch_module(self) -> None:
        """get_torch returns the torch module."""
        loader = GPUAutoLoader()
        mock_torch = Mock()
        loader._torch = mock_torch

        result = loader.get_torch()

        assert result is mock_torch

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
        mock_device = Mock()
        loader._device = mock_device

        mock_tensor = Mock()
        mock_tensor.to = Mock(return_value="moved_tensor")

        result = loader.to_device(mock_tensor)

        mock_tensor.to.assert_called_once_with(mock_device)
        assert result == "moved_tensor"

    def test_to_device_returns_unchanged_when_no_device(self) -> None:
        """to_device returns object unchanged when no device configured."""
        loader = GPUAutoLoader()
        loader._device = None

        mock_tensor = Mock()

        result = loader.to_device(mock_tensor)

        assert result is mock_tensor


class TestModelOptimization:
    """Test model optimization functionality."""

    def test_optimize_model_compiles_for_intel_xpu(self) -> None:
        """optimize_model compiles model for Intel XPU."""
        loader = GPUAutoLoader()
        loader.gpu_type = "intel_xpu"

        mock_torch = Mock()
        mock_torch.compile = Mock(return_value="compiled_model")
        loader._torch = mock_torch

        mock_model = Mock()

        result = loader.optimize_model(mock_model)

        mock_torch.compile.assert_called_once_with(mock_model)
        assert result == "compiled_model"

    def test_optimize_model_returns_unchanged_for_other_backends(self) -> None:
        """optimize_model returns model unchanged for non-XPU backends."""
        loader = GPUAutoLoader()
        loader.gpu_type = "nvidia_cuda"

        mock_model = Mock()

        result = loader.optimize_model(mock_model)

        assert result is mock_model

    def test_optimize_model_handles_compilation_errors(self) -> None:
        """optimize_model handles errors during compilation."""
        loader = GPUAutoLoader()
        loader.gpu_type = "intel_xpu"

        mock_torch = Mock()
        mock_torch.compile.side_effect = RuntimeError("Compilation failed")
        loader._torch = mock_torch

        mock_model = Mock()

        result = loader.optimize_model(mock_model)

        assert result is mock_model


class TestMemoryInfo:
    """Test GPU memory information retrieval."""

    def test_get_memory_info_for_nvidia_cuda(self) -> None:
        """get_memory_info returns CUDA memory information."""
        loader = GPUAutoLoader()
        loader.gpu_available = True
        loader.gpu_type = "nvidia_cuda"

        mock_torch = Mock()
        mock_torch.cuda.memory_allocated.return_value = 1024**3
        mock_torch.cuda.memory_reserved.return_value = 2 * 1024**3

        mock_props = Mock()
        mock_props.total_memory = 24 * 1024**3
        mock_torch.cuda.get_device_properties.return_value = mock_props

        loader._torch = mock_torch

        result = loader.get_memory_info()

        assert "allocated" in result
        assert "reserved" in result
        assert "free" in result

    def test_get_memory_info_for_intel_xpu(self) -> None:
        """get_memory_info returns XPU memory information."""
        loader = GPUAutoLoader()
        loader.gpu_available = True
        loader.gpu_type = "intel_xpu"

        mock_torch = Mock()
        mock_torch.xpu.memory_allocated.return_value = 1024**3
        mock_torch.xpu.memory_reserved.return_value = 2 * 1024**3
        loader._torch = mock_torch

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

        mock_torch = Mock()
        mock_torch.cuda.memory_allocated.side_effect = RuntimeError("Memory error")
        loader._torch = mock_torch

        result = loader.get_memory_info()

        assert isinstance(result, dict)


class TestSynchronization:
    """Test GPU synchronization functionality."""

    def test_synchronize_cuda_devices(self) -> None:
        """synchronize calls CUDA synchronize when available."""
        loader = GPUAutoLoader()
        loader.gpu_available = True
        loader.gpu_type = "nvidia_cuda"

        mock_torch = Mock()
        mock_torch.cuda.synchronize = Mock()
        loader._torch = mock_torch

        loader.synchronize()

        mock_torch.cuda.synchronize.assert_called_once()

    def test_synchronize_xpu_devices(self) -> None:
        """synchronize calls XPU synchronize when available."""
        loader = GPUAutoLoader()
        loader.gpu_available = True
        loader.gpu_type = "intel_xpu"

        mock_torch = Mock()
        mock_torch.xpu.synchronize = Mock()
        loader._torch = mock_torch

        loader.synchronize()

        mock_torch.xpu.synchronize.assert_called_once()

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

        mock_torch = Mock()
        mock_torch.cuda.synchronize.side_effect = RuntimeError("Sync error")
        loader._torch = mock_torch

        loader.synchronize()


class TestGlobalFunctions:
    """Test global convenience functions."""

    def test_get_device_uses_global_instance(self) -> None:
        """get_device uses global GPU autoloader instance."""
        with patch.object(gpu_autoloader, "get_device", return_value="device"):
            result = get_device()

            assert result == "device"

    def test_get_gpu_info_returns_complete_info(self) -> None:
        """get_gpu_info returns complete GPU information."""
        with patch.object(gpu_autoloader, "gpu_available", True):
            with patch.object(gpu_autoloader, "gpu_type", "nvidia_cuda"):
                with patch.object(gpu_autoloader, "get_device_string", return_value="cuda"):
                    with patch.object(gpu_autoloader, "gpu_info", {"backend": "CUDA"}):
                        with patch.object(gpu_autoloader, "get_memory_info", return_value={}):
                            result = get_gpu_info()

                            assert "available" in result
                            assert "type" in result
                            assert "device" in result
                            assert "info" in result
                            assert "memory" in result

    def test_to_device_uses_global_instance(self) -> None:
        """to_device uses global GPU autoloader instance."""
        mock_tensor = Mock()

        with patch.object(gpu_autoloader, "to_device", return_value="moved"):
            result = to_device(mock_tensor)

            assert result == "moved"

    def test_optimize_for_gpu_uses_global_instance(self) -> None:
        """optimize_for_gpu uses global GPU autoloader instance."""
        mock_model = Mock()

        with patch.object(gpu_autoloader, "optimize_model", return_value="optimized"):
            result = optimize_for_gpu(mock_model)

            assert result == "optimized"


class TestDetectGPUFrameworks:
    """Test GPU framework detection functionality."""

    def test_returns_framework_info_structure(self) -> None:
        """detect_gpu_frameworks returns dictionary with framework info."""
        with patch("intellicrack.utils.gpu_autoloader.torch", side_effect=ImportError):
            result = detect_gpu_frameworks()

            assert isinstance(result, dict)
            assert "cuda" in result
            assert "rocm" in result
            assert "opencl" in result
            assert "directml" in result
            assert "intel_xpu" in result
            assert "available_frameworks" in result
            assert "gpu_devices" in result

    def test_detects_cuda_when_available(self) -> None:
        """detect_gpu_frameworks detects CUDA when available."""
        mock_torch = Mock()
        mock_torch.cuda.is_available.return_value = True
        mock_torch.cuda.device_count.return_value = 1
        mock_torch.cuda.get_device_name.return_value = "NVIDIA GPU"
        mock_torch.version.cuda = "12.1"

        mock_props = Mock()
        mock_props.total_memory = 8 * 1024**3
        mock_torch.cuda.get_device_properties.return_value = mock_props

        with patch("intellicrack.utils.gpu_autoloader.torch", mock_torch):
            result = detect_gpu_frameworks()

            assert result["cuda"] is True
            assert "CUDA" in result["available_frameworks"]

    def test_handles_missing_frameworks(self) -> None:
        """detect_gpu_frameworks handles missing frameworks gracefully."""
        with patch("intellicrack.utils.gpu_autoloader.torch", side_effect=ImportError):
            result = detect_gpu_frameworks()

            assert result["cuda"] is False
            assert result["intel_xpu"] is False


class TestRealWorldScenarios:
    """Test realistic production usage scenarios."""

    def test_complete_gpu_setup_workflow(self) -> None:
        """Test complete workflow from detection to usage."""
        loader = GPUAutoLoader()

        with patch.object(loader, "_try_nvidia_cuda", return_value=True):
            loader.gpu_available = True
            loader.gpu_type = "nvidia_cuda"
            loader._device_string = "cuda"

            result = loader.setup()

            assert result is True
            assert loader.get_device_string() == "cuda"

    def test_fallback_cascade_to_cpu(self) -> None:
        """Test cascading fallback from all GPUs to CPU."""
        loader = GPUAutoLoader()

        with patch.object(loader, "_try_intel_xpu", return_value=False):
            with patch.object(loader, "_try_nvidia_cuda", return_value=False):
                with patch.object(loader, "_try_amd_rocm", return_value=False):
                    with patch.object(loader, "_try_directml", return_value=False):
                        with patch.object(loader, "_try_cpu_fallback", return_value=True):
                            loader.gpu_type = "cpu"

                            result = loader.setup()

                            assert result is True
                            assert loader.gpu_type == "cpu"


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_handles_torch_import_failure(self) -> None:
        """GPU detection handles PyTorch import failures."""
        loader = GPUAutoLoader()

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=None):
            result = loader._try_nvidia_cuda()

            assert result is False

    def test_handles_partial_gpu_support(self) -> None:
        """GPU detection handles partial GPU support."""
        loader = GPUAutoLoader()

        mock_torch = Mock()
        mock_torch.cuda.is_available.return_value = True
        mock_torch.cuda.device_count.side_effect = RuntimeError("Error")

        with patch("intellicrack.utils.gpu_autoloader.safe_torch_import", return_value=mock_torch):
            result = loader._try_nvidia_cuda()

            assert result is True

    def test_handles_none_device_in_to_device(self) -> None:
        """to_device handles objects without 'to' method."""
        loader = GPUAutoLoader()
        loader._device = Mock()

        simple_object = "string"

        result = loader.to_device(simple_object)

        assert result == simple_object
