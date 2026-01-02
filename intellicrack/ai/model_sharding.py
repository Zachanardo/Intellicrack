"""Model Sharding and Distribution Manager.

This module provides functionality for distributing large models across multiple GPUs
(NVIDIA CUDA and Intel XPU) using the Accelerate library and PyTorch. Supports advanced
distribution strategies including memory-aware device mapping, checkpoint loading with
distribution, and performance profiling of sharded models.

Key features:
- Automatic GPU device detection and capacity assessment
- Memory-aware device mapping using Accelerate's infer_auto_device_map
- Distributed checkpoint loading with streaming support
- Model profiling with per-iteration memory and timing metrics
- Pipeline parallelism stage grouping
- Device balance scoring for distribution quality evaluation

Classes:
    ModelShardingManager: Main class for managing model sharding operations

Functions:
    get_sharding_manager: Get or create global manager singleton instance

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

import gc
import time
import types
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    import torch

    TorchDtype = torch.dtype
    TorchModel = torch.nn.Module
    TorchDevice = torch.device
    TorchTensor = torch.Tensor
else:
    TorchDtype = object
    TorchModel = object
    TorchDevice = object
    TorchTensor = object

from ..utils.logger import get_logger


logger = get_logger(__name__)

APPLIED_GPU_OPTIMIZATIONS_MSG = "Applied GPU optimizations to model"

torch: types.ModuleType | None
Accelerator: type[Any] | None
dispatch_model: Callable[..., Any] | None
infer_auto_device_map: Callable[..., Any] | None
init_empty_weights: Callable[..., Any] | None
load_checkpoint_and_dispatch: Callable[..., Any] | None
AutoConfig: type[Any] | None
AutoModel: type[Any] | None
AutoModelForCausalLM: type[Any] | None

# Try importing PyTorch
try:
    import torch

    HAS_TORCH = True

    # Import unified GPU system
    try:
        from ..utils.gpu_autoloader import get_device, get_gpu_info, gpu_autoloader, optimize_for_gpu, to_device

        GPU_AUTOLOADER_AVAILABLE = True
    except ImportError:
        GPU_AUTOLOADER_AVAILABLE = False

except ImportError:
    torch = None
    HAS_TORCH = False
    GPU_AUTOLOADER_AVAILABLE = False

# Try importing accelerate for advanced model parallelism
try:
    from accelerate import Accelerator, dispatch_model, infer_auto_device_map, init_empty_weights, load_checkpoint_and_dispatch

    HAS_ACCELERATE = True
except ImportError as e:
    logger.exception("Import error in model_sharding: %s", e)
    HAS_ACCELERATE = False
    Accelerator = None
    dispatch_model = None
    infer_auto_device_map = None
    init_empty_weights = None
    load_checkpoint_and_dispatch = None

# Try importing transformers for model loading
try:
    from transformers import AutoConfig, AutoModel, AutoModelForCausalLM

    HAS_TRANSFORMERS = True
except ImportError as e:
    logger.exception("Import error in model_sharding: %s", e)
    AutoConfig = None
    AutoModel = None
    AutoModelForCausalLM = None
    HAS_TRANSFORMERS = False


class ModelShardingManager:
    """Manages model sharding across multiple GPUs.

    Main class for distributing large PyTorch models across multiple GPU devices
    (NVIDIA CUDA, Intel XPU) to overcome memory limitations and improve inference/training
    performance. Provides comprehensive GPU detection, memory management, device mapping,
    checkpoint loading, and performance profiling capabilities.

    Attributes:
        device_count: Number of available GPU devices detected.
        gpu_type: Type of GPU detected ('nvidia_cuda', 'intel_xpu', or 'cpu').
        unified_device: Device object from gpu_autoloader if available.
        device_properties: Dictionary mapping device IDs to hardware property dictionaries.
        shard_configs: Configuration dictionary for sharding parameters.

    Usage:
        manager = ModelShardingManager()
        device_map = manager.create_device_map(model_config)
        sharded_model = manager.shard_model(model, device_map=device_map)
        memory_info = manager.monitor_memory_usage()
    """

    def __init__(self) -> None:
        """Initialize the model sharding manager.

        Sets up GPU device tracking, memory properties, and sharding configuration.
        Automatically detects available GPU devices (NVIDIA CUDA or Intel XPU) and
        initializes their properties for use in model distribution operations.
        """
        self._initialize_gpu_info()
        self.device_properties: dict[int, dict[str, Any]] = {}
        self.shard_configs: dict[str, Any] = {}

        if self.device_count > 0 and HAS_TORCH:
            self._initialize_device_properties()
            logger.info("Initialized sharding manager with %d %s devices", self.device_count, self.gpu_type)
        else:
            logger.info("No GPUs detected, sharding disabled")

    def _initialize_gpu_info(self) -> None:
        """Initialize GPU device information.

        Queries available GPU devices and their types using either the gpu_autoloader
        utility or direct PyTorch CUDA interfaces. Sets device_count and gpu_type
        attributes based on detected hardware capabilities.
        """
        if GPU_AUTOLOADER_AVAILABLE:
            gpu_info = get_gpu_info()
            info_dict = gpu_info.get("info")
            if isinstance(info_dict, dict):
                device_count_val = info_dict.get("device_count", 0)
                self.device_count = device_count_val if isinstance(device_count_val, int) else 0
            else:
                self.device_count = 0 if gpu_info.get("available") else 0
            gpu_type_val = gpu_info.get("type")
            self.gpu_type = gpu_type_val if isinstance(gpu_type_val, str) else "cpu"
            self.unified_device = get_device()
        else:
            if HAS_TORCH and torch is not None and hasattr(torch, "cuda"):
                self.device_count = torch.cuda.device_count() if torch.cuda.is_available() else 0
            else:
                self.device_count = 0
            self.gpu_type = "cuda" if self.device_count > 0 else "cpu"
            self.unified_device = None

    def _initialize_device_properties(self) -> None:
        """Initialize properties for all available devices.

        Iterates through all detected GPU devices and populates device_properties
        dictionary with hardware-specific information (memory, processor count, etc.)
        based on device type (NVIDIA CUDA or Intel XPU).
        """
        for i in range(self.device_count):
            if self.gpu_type == "nvidia_cuda":
                self._initialize_nvidia_device_properties(i)
            elif self.gpu_type == "intel_xpu" and hasattr(torch, "xpu"):
                self._initialize_intel_xpu_device_properties(i)

    def _initialize_nvidia_device_properties(self, device_id: int) -> None:
        """Initialize NVIDIA CUDA device properties.

        Queries NVIDIA CUDA device properties and stores device name, total memory,
        compute capability (major/minor versions), and multiprocessor count.

        Args:
            device_id: Index of the CUDA device to initialize properties for.
        """
        if torch is not None and hasattr(torch, "cuda"):
            props = torch.cuda.get_device_properties(device_id)
            self.device_properties[device_id] = {
                "name": props.name,
                "total_memory": props.total_memory,
                "major": props.major,
                "minor": props.minor,
                "multi_processor_count": props.multi_processor_count,
            }

    def _initialize_intel_xpu_device_properties(self, device_id: int) -> None:
        """Initialize Intel XPU device properties.

        Queries Intel XPU device properties and stores device name, total memory,
        and device type. Gracefully handles missing XPU API functions.

        Args:
            device_id: Index of the XPU device to initialize properties for.
        """
        self.device_properties[device_id] = {
            "name": torch.xpu.get_device_name(device_id) if hasattr(torch.xpu, "get_device_name") else f"Intel XPU {device_id}",
            "total_memory": 0,
            "device_type": "xpu",
        }
        if hasattr(torch.xpu, "get_device_properties"):
            try:
                props = torch.xpu.get_device_properties(device_id)
                if hasattr(props, "total_memory"):
                    self.device_properties[device_id]["total_memory"] = props.total_memory
            except (AttributeError, RuntimeError):
                pass

    def get_sharding_info(self) -> dict[str, object]:
        """Get information about current sharding configuration.

        Returns a comprehensive dictionary containing device count, available devices,
        memory information, and current device state.

        Returns:
            Dictionary with keys 'available', 'device_count', 'devices', 'current_device',
            and 'accelerate_available' describing the current sharding configuration.
        """
        info = {
            "available": self.device_count > 1,
            "device_count": self.device_count,
            "devices": self.device_properties,
            "current_device": self._get_current_device(),
            "accelerate_available": HAS_ACCELERATE,
        }

        if self.device_count > 0 and HAS_TORCH:
            self._add_memory_info_to_devices(info)

        return info

    def _add_memory_info_to_devices(self, info: dict[str, object]) -> None:
        """Add memory information to device info.

        Updates the info dictionary with current memory usage for each device,
        including allocated, reserved, and free memory.

        Args:
            info: Dictionary to update with memory information for each device.
        """
        for i in range(self.device_count):
            if self.gpu_type == "nvidia_cuda":
                self._add_nvidia_memory_info(info, i)
            elif self.gpu_type == "intel_xpu" and hasattr(torch, "xpu"):
                self._add_intel_xpu_memory_info(info, i)

    def _add_nvidia_memory_info(self, info: dict[str, object], device_id: int) -> None:
        """Add NVIDIA CUDA memory information to device info.

        Updates device info dictionary with allocated, reserved, and free memory
        measurements from CUDA device.

        Args:
            info: Dictionary containing device information to update.
            device_id: Index of the CUDA device to query memory for.
        """
        if torch is not None and hasattr(torch, "cuda"):
            torch.cuda.set_device(device_id)
            devices = info["devices"]
            if isinstance(devices, dict) and device_id in devices:
                device_info = devices[device_id]
                if isinstance(device_info, dict):
                    device_info["allocated_memory"] = torch.cuda.memory_allocated(device_id)
                    device_info["reserved_memory"] = torch.cuda.memory_reserved(device_id)
                    total_mem = device_info.get("total_memory", 0)
                    if isinstance(total_mem, int):
                        device_info["free_memory"] = total_mem - torch.cuda.memory_allocated(device_id)

    def _add_intel_xpu_memory_info(self, info: dict[str, object], device_id: int) -> None:
        """Add Intel XPU memory information to device info.

        Updates device info dictionary with allocated and reserved memory for Intel XPU.

        Args:
            info: Dictionary containing device information to update.
            device_id: Index of the XPU device to query memory for.
        """
        if torch is None or not hasattr(torch, "xpu"):
            return
        if hasattr(torch.xpu, "set_device"):
            torch.xpu.set_device(device_id)
        devices = info["devices"]
        if isinstance(devices, dict) and device_id in devices:
            device_info = devices[device_id]
            if isinstance(device_info, dict):
                if hasattr(torch.xpu, "memory_allocated"):
                    device_info["allocated_memory"] = torch.xpu.memory_allocated(device_id)
                if hasattr(torch.xpu, "memory_reserved"):
                    device_info["reserved_memory"] = torch.xpu.memory_reserved(device_id)

    def _get_current_device(self) -> int:
        """Get current device index.

        Queries the currently active GPU device, supporting both NVIDIA CUDA,
        Intel XPU, and unified GPU autoloader configurations.

        Returns:
            Integer index of the current device (defaults to 0 for CPU or single device).
        """
        if GPU_AUTOLOADER_AVAILABLE and self.unified_device:
            device_str = str(self.unified_device)
            return int(device_str.split(":")[1]) if ":" in device_str else 0
        if torch is not None and hasattr(torch, "cuda") and (self.gpu_type == "nvidia_cuda" and torch.cuda.is_available()):
            return torch.cuda.current_device()
        if torch is not None and hasattr(torch, "xpu") and (self.gpu_type == "intel_xpu" and hasattr(torch.xpu, "current_device")):
            return torch.xpu.current_device()
        return 0

    def create_device_map(
        self,
        model_config_or_path: str | dict[str, Any],
        max_memory: dict[int, str] | None = None,
        no_split_module_classes: list[str] | None = None,
        dtype: TorchDtype | None = None,
    ) -> dict[str, object]:
        """Create a device map for model sharding.

        Generates an optimal device allocation map using the Accelerate library's
        infer_auto_device_map functionality, considering memory constraints and
        module properties. Falls back to simple device mapping if Accelerate is
        unavailable or single device is detected.

        Args:
            model_config_or_path: Model configuration dictionary or path to pretrained model.
            max_memory: Dictionary mapping device IDs to maximum memory strings (e.g., "10GB").
                If None, uses balanced allocation based on device properties.
            no_split_module_classes: List of module class names that should not be split
                across devices. Important for layers with specific locality requirements.
            dtype: PyTorch data type for model parameters (e.g., torch.float16, torch.float32).
                Affects memory calculations for device mapping.

        Returns:
            Dictionary mapping module names or prefixes to device indices, representing
            optimal distribution of model layers across available devices.
        """
        if not HAS_ACCELERATE:
            logger.warning("Accelerate not available, using simple device map")
            return self._create_simple_device_map()

        if self.device_count <= 1:
            return {"": 0} if self.device_count == 1 else {"": "cpu"}

        config: Any
        if isinstance(model_config_or_path, str) and HAS_TRANSFORMERS and AutoConfig is not None:
            config = AutoConfig.from_pretrained(model_config_or_path)
        else:
            config = model_config_or_path

        # Set default max memory if not provided
        if max_memory is None:
            max_memory = self._get_balanced_memory()

        try:
            if init_empty_weights is None or infer_auto_device_map is None:
                return self._create_simple_device_map()

            with init_empty_weights():
                if HAS_TRANSFORMERS and AutoModelForCausalLM is not None:
                    model = AutoModelForCausalLM.from_config(config)
                else:
                    logger.warning("Transformers not available")
                    return self._create_simple_device_map()

                device_map_result = infer_auto_device_map(
                    model,
                    max_memory=max_memory,
                    no_split_module_classes=no_split_module_classes,
                    dtype=dtype,
                )

            logger.info("Created device map: %s", device_map_result)
            return device_map_result if isinstance(device_map_result, dict) else self._create_simple_device_map()

        except Exception as e:
            logger.exception("Failed to create device map: %s", e)
            return self._create_simple_device_map()

    def _create_simple_device_map(self) -> dict[str, object]:
        """Create a simple device map for basic sharding.

        Generates a fallback device map when advanced sharding capabilities are
        unavailable. Distributes embedding and layer components across devices,
        placing final layers on the last device.

        Returns:
            Dictionary mapping component names to device indices for basic distribution.
        """
        if self.device_count == 0:
            return {"": "cpu"}
        if self.device_count == 1:
            return {"": 0}
        # Simple layer-based distribution
        return {
            "embed_tokens": 0,
            "layers": list(range(self.device_count)),
            "norm": self.device_count - 1,
            "lm_head": self.device_count - 1,
        }

    def _get_balanced_memory(self) -> dict[int, str]:
        """Get balanced memory allocation across devices.

        Calculates balanced memory budgets for each device based on available total
        memory, allocating 90% of total capacity for model layers with 10% reserved
        for overhead.

        Returns:
            Dictionary mapping device IDs to memory allocation strings (e.g., {"0": "20GB"}).
        """
        if self.device_count == 0:
            return {}

        max_memory: dict[int, str] = {}
        for i in range(self.device_count):
            if i in self.device_properties:
                total_memory_obj = self.device_properties[i].get("total_memory", 0)
                if isinstance(total_memory_obj, int):
                    usable_memory = int(total_memory_obj * 0.9)
                    max_memory[i] = f"{usable_memory}B"
                else:
                    max_memory[i] = "20GB"
            else:
                max_memory[i] = "20GB"

        logger.info("Balanced memory allocation: %s", max_memory)
        return max_memory

    def shard_model(
        self,
        model: TorchModel,
        device_map: dict[str, object] | None = None,
        max_memory: dict[int, str] | None = None,
        offload_folder: str | None = None,
        offload_state_dict: bool = False,
    ) -> TorchModel:
        """Shard a model across multiple devices.

        Distributes model layers across available GPU devices for efficient memory usage
        and parallel computation. Applies GPU optimizations before and after sharding,
        with fallback to single-device or CPU modes for limited hardware.

        Args:
            model: PyTorch model to distribute across devices.
            device_map: Dictionary mapping module names to device indices. If None,
                creates a simple device map automatically.
            max_memory: Maximum memory per device in string format (e.g., "10GB").
                If None, uses balanced allocation based on device properties.
            offload_folder: Path to folder for CPU offloading when device memory is exceeded.
            offload_state_dict: Whether to offload model state dict to disk during loading.

        Returns:
            Model with layers distributed according to device_map, with GPU optimizations applied.
        """
        if not HAS_ACCELERATE:
            return self._shard_model_without_accelerate(model)

        if self.device_count <= 1:
            return self._shard_model_single_device(model)

        if device_map is None:
            device_map = self._create_simple_device_map()

        model = self._apply_pre_sharding_optimizations(model)

        return self._dispatch_model_across_devices(model, device_map, max_memory, offload_folder, offload_state_dict)

    def _shard_model_without_accelerate(self, model: TorchModel) -> TorchModel:
        """Shard model without accelerate library.

        Applies GPU optimizations to model when Accelerate is unavailable,
        using gpu_autoloader utilities for device placement.

        Args:
            model: Model to optimize and place on device.

        Returns:
            Optimized model with GPU acceleration applied.
        """
        logger.warning("Accelerate not available, model not sharded")
        if GPU_AUTOLOADER_AVAILABLE:
            if optimize_for_gpu is not None:
                optimized = optimize_for_gpu(model)
                if optimized is not None:
                    model = optimized
                    logger.info(APPLIED_GPU_OPTIMIZATIONS_MSG)
            device_result = to_device(model)
            return device_result if device_result is not None else model
        return model

    def _shard_model_single_device(self, model: TorchModel) -> TorchModel:
        """Shard model for single device.

        Optimizes model placement on a single GPU device without sharding.
        Applies GPU-specific optimizations for maximum performance on one device.

        Args:
            model: Model to place on single device.

        Returns:
            Model optimized and placed on the single available device.
        """
        logger.info("Single GPU - no sharding needed")
        if GPU_AUTOLOADER_AVAILABLE:
            if optimize_for_gpu is not None:
                optimized = optimize_for_gpu(model)
                if optimized is not None:
                    model = optimized
                    logger.info(APPLIED_GPU_OPTIMIZATIONS_MSG)
            device_result = to_device(model)
            return device_result if device_result is not None else model
        if self.device_count == 1 and torch is not None and hasattr(torch, "cuda"):
            return model.to(0) if torch.cuda.is_available() else model
        return model

    def _apply_pre_sharding_optimizations(self, model: TorchModel) -> TorchModel:
        """Apply optimizations before sharding.

        Applies GPU-specific optimizations to model structure and parameters
        prior to distribution across devices.

        Args:
            model: Model to optimize.

        Returns:
            Optimized model ready for sharding.
        """
        if GPU_AUTOLOADER_AVAILABLE and optimize_for_gpu is not None:
            try:
                optimized = optimize_for_gpu(model)
                if optimized is not None:
                    model = optimized
                    logger.info("Applied GPU optimizations before sharding")
            except Exception as e:
                logger.debug("Could not optimize model before sharding: %s", e)
        return model

    def _dispatch_model_across_devices(
        self,
        model: TorchModel,
        device_map: dict[str, object],
        max_memory: dict[int, str] | None,
        offload_folder: str | None,
        offload_state_dict: bool,
    ) -> TorchModel:
        """Dispatch model across multiple devices.

        Distributes model layers to devices using the Accelerate library's dispatch_model
        function. Applies post-sharding optimizations and handles failures with fallback.

        Args:
            model: Model to distribute across devices.
            device_map: Device mapping for layer distribution.
            max_memory: Memory constraints per device.
            offload_folder: CPU offloading folder path.
            offload_state_dict: Whether to offload state dict.

        Returns:
            Model distributed across devices with optimizations applied.

        Raises:
            Logs exceptions and returns fallback result instead of raising.
        """
        try:
            if dispatch_model is None:
                logger.exception("dispatch_model not available")
                return to_device(model) if GPU_AUTOLOADER_AVAILABLE else model

            model = dispatch_model(
                model,
                device_map=device_map,
                max_memory=max_memory,
                offload_folder=offload_folder,
                offload_state_dict=offload_state_dict,
            )
            logger.info("Model successfully sharded across devices")
            return self._apply_post_sharding_optimizations(model)
        except Exception as e:
            logger.exception("Failed to shard model: %s", e)
            return to_device(model) if GPU_AUTOLOADER_AVAILABLE else model

    def _apply_post_sharding_optimizations(self, model: TorchModel) -> TorchModel:
        """Apply optimizations after sharding.

        Applies GPU autoloader optimizations to sharded model for improved performance
        across distributed devices.

        Args:
            model: Sharded model to optimize.

        Returns:
            Sharded model with post-distribution optimizations applied.
        """
        if GPU_AUTOLOADER_AVAILABLE and gpu_autoloader is not None:
            try:
                optimized = gpu_autoloader(model)
                if optimized is not None:
                    model = optimized
                    logger.info("Applied autoloader optimizations after sharding")
            except Exception as e:
                logger.debug("Could not apply autoloader optimizations: %s", e)
        return model

    def load_sharded_checkpoint(
        self,
        model: TorchModel,
        checkpoint: str | Path,
        device_map: dict[str, object] | None = None,
        max_memory: dict[int, str] | None = None,
        no_split_module_classes: list[str] | None = None,
        dtype: TorchDtype | None = None,
    ) -> TorchModel:
        """Load a checkpoint and shard it across devices.

        Loads model weights from checkpoint file and distributes them across available
        devices according to device_map. Handles single-device and multi-device scenarios
        with appropriate fallbacks.

        Args:
            model: Model architecture to load checkpoint into.
            checkpoint: Path to checkpoint file containing model weights.
            device_map: Device mapping for layer distribution. If None, creates simple map.
            max_memory: Memory constraints per device in string format.
            no_split_module_classes: Module classes to keep on single device.
            dtype: Data type for model parameters during loading.

        Returns:
            Model with checkpoint weights loaded and distributed across devices.
        """
        if not HAS_ACCELERATE:
            return self._load_checkpoint_without_accelerate(model, checkpoint)

        if self.device_count <= 1:
            return self._load_checkpoint_single_device(model, checkpoint)

        if device_map is None:
            device_map = self._create_simple_device_map()

        return self._load_and_dispatch_checkpoint(
            model,
            checkpoint,
            device_map,
            max_memory,
            no_split_module_classes,
            dtype,
        )

    def _load_checkpoint_without_accelerate(self, model: TorchModel, checkpoint: str | Path) -> TorchModel:
        """Load checkpoint without accelerate.

        Loads checkpoint weights into model using standard PyTorch methods and applies
        GPU optimizations when available.

        Args:
            model: Model architecture to load weights into.
            checkpoint: Path to checkpoint file.

        Returns:
            Model with checkpoint weights loaded and GPU optimizations applied.
        """
        logger.warning("Accelerate not available, loading normally")
        if HAS_TORCH and torch is not None:
            model.load_state_dict(torch.load(str(checkpoint)))
            return self._apply_gpu_optimizations(model)
        return model

    def _load_checkpoint_single_device(self, model: TorchModel, checkpoint: str | Path) -> TorchModel:
        """Load checkpoint for a single device.

        Loads checkpoint into model on single GPU device with GPU optimizations.

        Args:
            model: Model to load checkpoint into.
            checkpoint: Path to checkpoint file.

        Returns:
            Model with checkpoint loaded on single GPU device.
        """
        logger.info("Single GPU - loading normally")
        if HAS_TORCH and torch is not None:
            model.load_state_dict(torch.load(str(checkpoint)))
            return self._apply_gpu_optimizations(model)
        return model

    def _load_and_dispatch_checkpoint(
        self,
        model: TorchModel,
        checkpoint: str | Path,
        device_map: dict[str, object],
        max_memory: dict[int, str] | None,
        no_split_module_classes: list[str] | None,
        dtype: TorchDtype | None,
    ) -> TorchModel:
        """Load and dispatch checkpoint across devices.

        Uses Accelerate's load_checkpoint_and_dispatch to efficiently load model weights
        and distribute them across multiple devices in a streaming fashion.

        Args:
            model: Model architecture to load checkpoint into.
            checkpoint: Path to checkpoint file.
            device_map: Device mapping for layer distribution.
            max_memory: Memory constraints per device.
            no_split_module_classes: Module classes to keep on single device.
            dtype: Data type for model parameters.

        Returns:
            Model with checkpoint loaded and distributed across devices.

        Raises:
            Logs exceptions and returns fallback result instead of raising.
        """
        try:
            if load_checkpoint_and_dispatch is None:
                logger.exception("load_checkpoint_and_dispatch not available")
                return self._fallback_checkpoint_load(model, checkpoint)

            model = load_checkpoint_and_dispatch(
                model,
                str(checkpoint),
                device_map=device_map,
                max_memory=max_memory,
                no_split_module_classes=no_split_module_classes,
                dtype=dtype,
            )
            logger.info("Checkpoint loaded and sharded across devices")
            return self._apply_autoloader_optimizations(model)
        except Exception as e:
            logger.exception("Failed to load sharded checkpoint: %s", e)
            return self._fallback_checkpoint_load(model, checkpoint)

    def _apply_gpu_optimizations(self, model: TorchModel) -> TorchModel:
        """Apply GPU optimizations to the model.

        Applies GPU-specific optimizations and device placement using available
        optimization utilities.

        Args:
            model: Model to optimize.

        Returns:
            Model with GPU optimizations applied.
        """
        if GPU_AUTOLOADER_AVAILABLE and optimize_for_gpu is not None:
            try:
                optimized = optimize_for_gpu(model)
                if optimized is not None:
                    model = optimized
                    logger.info(APPLIED_GPU_OPTIMIZATIONS_MSG)
            except Exception as e:
                logger.debug("Could not optimize model: %s", e)
        if GPU_AUTOLOADER_AVAILABLE:
            device_result = to_device(model)
            return device_result if device_result is not None else model
        return model

    def _apply_autoloader_optimizations(self, model: TorchModel) -> TorchModel:
        """Apply autoloader optimizations after sharding.

        Applies autoloader-specific optimizations to distributed model.

        Args:
            model: Distributed model to optimize.

        Returns:
            Model with autoloader optimizations applied.
        """
        if GPU_AUTOLOADER_AVAILABLE and gpu_autoloader is not None:
            try:
                optimized = gpu_autoloader(model)
                if optimized is not None:
                    model = optimized
                    logger.info("Applied autoloader optimizations to sharded checkpoint")
            except Exception as e:
                logger.debug("Could not apply autoloader optimizations: %s", e)
        return model

    def _fallback_checkpoint_load(self, model: TorchModel, checkpoint: str | Path) -> TorchModel:
        """Fallback checkpoint loading in case of failure.

        Simple checkpoint loading fallback when distributed loading fails.
        Uses standard PyTorch loading and applies GPU optimizations.

        Args:
            model: Model to load checkpoint into.
            checkpoint: Path to checkpoint file.

        Returns:
            Model with checkpoint loaded.
        """
        if HAS_TORCH and torch is not None:
            model.load_state_dict(torch.load(str(checkpoint)))
            return self._apply_gpu_optimizations(model)
        return model

    def estimate_model_memory(
        self,
        model_config: dict[str, object],
        dtype: TorchDtype | None = None,
    ) -> dict[str, object]:
        """Estimate memory requirements for a model.

        Calculates total model memory footprint based on parameter count and data type.
        Estimates per-device memory allocation and whether model fits in available memory.
        Uses provided num_parameters or derives from hidden_size and num_hidden_layers.

        Args:
            model_config: Dictionary with model configuration. Expected keys are
                'num_parameters', 'hidden_size', 'num_hidden_layers', 'vocab_size'.
            dtype: PyTorch data type for parameters. Defaults to float16 if available.

        Returns:
            Dictionary containing 'param_count', 'model_memory_bytes', 'total_memory_bytes',
            'memory_per_device', 'device_distribution', and 'fits_in_memory' flag.
        """
        if dtype is None and HAS_TORCH and torch is not None:
            dtype = torch.float16

        param_count_obj = model_config.get("num_parameters", 0)
        if not isinstance(param_count_obj, int):
            param_count_obj = 0
        param_count = param_count_obj

        if param_count == 0:
            hidden_size_obj = model_config.get("hidden_size", 4096)
            num_layers_obj = model_config.get("num_hidden_layers", 32)
            vocab_size_obj = model_config.get("vocab_size", 32000)

            hidden_size = hidden_size_obj if isinstance(hidden_size_obj, int) else 4096
            num_layers = num_layers_obj if isinstance(num_layers_obj, int) else 32
            vocab_size = vocab_size_obj if isinstance(vocab_size_obj, int) else 32000

            param_count = (
                vocab_size * hidden_size
                + num_layers * 4 * hidden_size * hidden_size
                + num_layers * 4 * hidden_size * hidden_size
                + 2 * num_layers * hidden_size
            )

        bytes_per_param = 2 if (torch is not None and hasattr(torch, "float16") and dtype == torch.float16) else 4
        model_memory = param_count * bytes_per_param

        total_memory = int(model_memory * 1.25)

        device_distribution: dict[int, dict[str, object]] = {}
        if self.device_count > 0:
            memory_per_device = total_memory // self.device_count
            for i in range(self.device_count):
                device_memory_obj = self.device_properties[i].get("total_memory", 0)
                if isinstance(device_memory_obj, int) and device_memory_obj > 0:
                    device_memory = device_memory_obj
                    device_distribution[i] = {
                        "allocated": memory_per_device,
                        "available": device_memory,
                        "usage_percent": (memory_per_device / device_memory) * 100,
                    }

        fits_in_memory = False
        if device_distribution:
            usage_checks: list[bool] = []
            for d in device_distribution.values():
                usage_val = d.get("usage_percent")
                if isinstance(usage_val, (int, float)):
                    usage_checks.append(float(usage_val) < 90)
                else:
                    usage_checks.append(False)
            fits_in_memory = all(usage_checks)

        return {
            "param_count": param_count,
            "model_memory_bytes": model_memory,
            "total_memory_bytes": total_memory,
            "memory_per_device": total_memory // max(self.device_count, 1),
            "device_distribution": device_distribution,
            "fits_in_memory": fits_in_memory,
        }

    def optimize_device_map(
        self,
        device_map: dict[str, object],
        model_config: dict[str, object],
        layer_wise: bool = True,
    ) -> dict[str, object]:
        """Optimize a device map for better performance.

        Redistributes model layers across devices with balanced load distribution.
        Splits layers evenly among devices and places final layers on last device.
        Returns original map if single device or layer_wise optimization disabled.

        Args:
            device_map: Initial device map to optimize (may be returned unchanged).
            model_config: Model configuration containing 'num_hidden_layers' parameter.
            layer_wise: If True, redistribute layers for balanced load. If False, returns original map.

        Returns:
            Optimized device map with balanced layer distribution or original map if unchanged.
        """
        if not layer_wise or self.device_count <= 1:
            return device_map

        # Get layer configuration
        num_layers_obj = model_config.get("num_hidden_layers", 32)
        num_layers = num_layers_obj if isinstance(num_layers_obj, int) else 32
        layers_per_device = num_layers // self.device_count
        remainder = num_layers % self.device_count

        # Create optimized map
        optimized_map: dict[str, object] = {
            "embeddings": 0,
            "encoder": {},
            "decoder": {},
        }

        # Distribute layers
        current_layer = 0
        for device in range(self.device_count):
            device_layers = layers_per_device
            if device < remainder:
                device_layers += 1

            for layer in range(current_layer, current_layer + device_layers):
                encoder_dict = optimized_map["encoder"]
                decoder_dict = optimized_map["decoder"]
                if isinstance(encoder_dict, dict):
                    encoder_dict[f"layer.{layer}"] = device
                if isinstance(decoder_dict, dict):
                    decoder_dict[f"layer.{layer}"] = device

            current_layer += device_layers

        # Put final layers on last device
        last_device = self.device_count - 1
        optimized_map["pooler"] = last_device
        optimized_map["lm_head"] = last_device

        logger.info("Optimized device map for %d layers across %d devices", num_layers, self.device_count)
        return optimized_map

    def monitor_memory_usage(self) -> dict[int, dict[str, object]]:
        """Monitor memory usage across all devices.

        Queries current memory utilization for all available GPU devices,
        returning allocated, reserved, and free memory per device.

        Returns:
            Dictionary mapping device IDs to memory information dictionaries with keys
            like 'allocated_gb', 'reserved_gb', 'free_gb', 'total_gb', 'usage_percent'.
        """
        memory_info: dict[int, dict[str, object]] = {}

        if not HAS_TORCH or self.device_count == 0:
            return memory_info

        for i in range(self.device_count):
            if self.gpu_type == "nvidia_cuda":
                memory_info[i] = self._get_nvidia_memory_usage(i)
            elif self.gpu_type == "intel_xpu" and hasattr(torch, "xpu"):
                memory_info[i] = self._get_intel_xpu_memory_usage(i)

        return memory_info

    def _get_nvidia_memory_usage(self, device_id: int) -> dict[str, object]:
        """Get NVIDIA CUDA memory usage for a device.

        Queries current memory statistics from NVIDIA CUDA device including allocated,
        reserved, free, and total memory. Computes usage percentage.

        Args:
            device_id: Index of the CUDA device to query.

        Returns:
            Dictionary with 'allocated_gb', 'reserved_gb', 'free_gb', 'total_gb',
            and 'usage_percent' keys. Empty dict if CUDA unavailable.
        """
        if torch is None or not hasattr(torch, "cuda"):
            return {}

        allocated = torch.cuda.memory_allocated(device_id) / (1024**3)
        reserved = torch.cuda.memory_reserved(device_id) / (1024**3)

        total_memory_obj = self.device_properties[device_id].get("total_memory", 0)
        total = (total_memory_obj / (1024**3)) if isinstance(total_memory_obj, int) else 0.0

        return {
            "allocated_gb": allocated,
            "reserved_gb": reserved,
            "free_gb": total - allocated if total > 0 else 0.0,
            "total_gb": total,
            "usage_percent": (allocated / total) * 100 if total > 0 else 0.0,
        }

    def _get_intel_xpu_memory_usage(self, device_id: int) -> dict[str, object]:
        """Get Intel XPU memory usage for a device.

        Queries Intel XPU device memory statistics including allocated, reserved,
        free, and total memory. Gracefully handles missing XPU API functions.

        Args:
            device_id: Index of the XPU device to query.

        Returns:
            Dictionary with device memory information. Includes available metrics
            from XPU API with 'device_type' and 'device_id' always present.
        """
        memory_info: dict[str, object] = {"device_type": "xpu", "device_id": device_id}

        if torch is not None and hasattr(torch, "xpu"):
            if hasattr(torch.xpu, "memory_allocated"):
                allocated = torch.xpu.memory_allocated(device_id) / (1024**3)
                memory_info["allocated_gb"] = allocated

            if hasattr(torch.xpu, "memory_reserved"):
                reserved = torch.xpu.memory_reserved(device_id) / (1024**3)
                memory_info["reserved_gb"] = reserved

            if device_id in self.device_properties:
                total_memory_obj = self.device_properties[device_id].get("total_memory")
                if isinstance(total_memory_obj, int) and total_memory_obj > 0:
                    total = total_memory_obj / (1024**3)
                    memory_info["total_gb"] = total
                    allocated_gb = memory_info.get("allocated_gb")
                    if isinstance(allocated_gb, (int, float)):
                        memory_info["free_gb"] = total - allocated_gb
                        memory_info["usage_percent"] = (allocated_gb / total) * 100

        return memory_info

    def cleanup_memory(self) -> None:
        """Clean up GPU memory across all devices.

        Clears GPU cache and runs garbage collection to free unused memory
        on all available CUDA or XPU devices.
        """
        if not HAS_TORCH or self.device_count == 0 or torch is None:
            return

        for i in range(self.device_count):
            if self.gpu_type == "nvidia_cuda" and hasattr(torch, "cuda"):
                torch.cuda.set_device(i)
                torch.cuda.empty_cache()
            elif self.gpu_type == "intel_xpu" and hasattr(torch, "xpu"):
                if hasattr(torch.xpu, "set_device"):
                    torch.xpu.set_device(i)
                if hasattr(torch.xpu, "empty_cache"):
                    torch.xpu.empty_cache()

        gc.collect()
        logger.info("Cleaned up memory on all devices")

    def get_device_balance_score(self, device_map: dict[str, Any]) -> float:
        """Calculate balance score for a device map.

        Evaluates distribution uniformity across devices using standard deviation.
        Returns 1.0 for perfectly balanced maps and lower scores for imbalanced ones.

        Args:
            device_map: Dictionary mapping module names to integer device indices.

        Returns:
            Float score between 0 and 1, where 1.0 is perfectly balanced (all devices
            have equal module count) and 0.0 means all modules on one device.
        """
        if self.device_count <= 1:
            return 1.0

        # Count modules per device
        device_counts: dict[int, int] = {}
        for device in device_map.values():
            if isinstance(device, int):
                device_counts[device] = device_counts.get(device, 0) + 1

        if not device_counts:
            return 0.0

        # Calculate balance
        avg_count = sum(device_counts.values()) / len(device_counts)
        variance = sum((count - avg_count) ** 2 for count in device_counts.values())
        std_dev = (variance / len(device_counts)) ** 0.5

        # Normalize to 0-1 (lower std_dev = higher score)
        max_std_dev = avg_count  # Worst case: all on one device
        return 1 - (std_dev / max_std_dev) if max_std_dev > 0 else 1.0

    def create_pipeline_parallel_groups(
        self,
        num_stages: int | None = None,
    ) -> list[list[int]]:
        """Create process groups for pipeline parallelism.

        Groups consecutive devices into pipeline stages for pipeline parallelism training.
        Each stage processes different model layers sequentially. Distributes devices
        evenly across requested stages.

        Args:
            num_stages: Number of pipeline stages to create. If None, uses device_count.
                Will be clamped to device_count if larger.

        Returns:
            List of device groups where each inner list contains consecutive device IDs
            forming a single pipeline stage.
        """
        if num_stages is None:
            num_stages = self.device_count

        if num_stages > self.device_count:
            logger.warning(
                "Requested %d stages but only %d devices available",
                num_stages,
                self.device_count,
            )
            num_stages = self.device_count

        # Create balanced groups
        devices_per_stage = self.device_count // num_stages
        remainder = self.device_count % num_stages

        groups = []
        device_idx = 0

        for stage in range(num_stages):
            stage_devices = devices_per_stage
            if stage < remainder:
                stage_devices += 1

            group = list(range(device_idx, device_idx + stage_devices))
            groups.append(group)
            device_idx += stage_devices

        logger.info("Created %d pipeline parallel groups: %s", len(groups), groups)
        return groups

    def profile_model_distribution(
        self,
        model: TorchModel,
        sample_input: Any,
        device_map: dict[str, object],
        num_iterations: int = 10,
    ) -> dict[str, object]:
        """Profile model performance with given distribution.

        Measures forward pass latency and memory consumption for distributed model.
        Includes warmup iterations, per-iteration metrics, and overall statistics.
        Computes device balance score for the given distribution.

        Args:
            model: Distributed model to profile.
            sample_input: Representative input tensor for profiling iterations.
            device_map: Device distribution map being profiled.
            num_iterations: Number of forward passes to measure (default 10).

        Returns:
            Dictionary containing 'forward_time_ms' (average/min/max/all), 'memory_usage_bytes'
            (start/end/peak/increase), 'memory_profile' (per-iteration and averages),
            'balance_score', 'num_devices', and 'device_map'.
        """
        if not HAS_TORCH:
            logger.exception("PyTorch required for profiling")
            return {}

        logger.info("Profiling model distribution over %d iterations", num_iterations)

        inputs = self._prepare_inputs_for_profiling(sample_input)
        self._warmup_model(model, inputs)

        forward_times: list[float] = []
        memory_usage: list[dict[str, object]] = []
        start_memory = self._get_initial_memory()

        for i in range(num_iterations):
            iteration_results = self._profile_single_iteration(model, inputs, i)
            forward_time_obj = iteration_results.get("forward_time", 0.0)
            memory_info_obj = iteration_results.get("memory_info", {})
            if isinstance(forward_time_obj, (int, float)):
                forward_times.append(float(forward_time_obj))
            if isinstance(memory_info_obj, dict):
                memory_usage.append(memory_info_obj)

        end_memory, peak_memory = self._get_final_memory(start_memory)

        return self._compile_profiling_results(
            device_map,
            forward_times,
            memory_usage,
            start_memory,
            end_memory,
            peak_memory,
        )

    def _prepare_inputs_for_profiling(self, sample_input: Any) -> Any:
        """Prepare inputs for profiling by moving to appropriate device.

        Moves input tensor to GPU device using available autoloader or native PyTorch.

        Args:
            sample_input: Input data to move to GPU device.

        Returns:
            Input data on GPU device, or original if device movement unavailable.
        """
        if GPU_AUTOLOADER_AVAILABLE:
            result = to_device(sample_input)
            return result if result is not None else sample_input
        if hasattr(sample_input, "to") and self.device_count > 0:
            gpu_type_str = str(self.gpu_type)
            device_type = gpu_type_str.split("_", maxsplit=1)[0] if "_" in gpu_type_str else "cuda"
            return sample_input.to(device_type)
        return sample_input

    def _warmup_model(self, model: TorchModel, inputs: Any) -> None:
        """Warmup model with a few iterations.

        Runs 3 forward passes without gradient tracking to stabilize timing measurements
        before actual profiling. Helps JIT compilation and cache warm-up.

        Args:
            model: Model to warmup.
            inputs: Input data for warmup iterations.
        """
        if torch is not None:
            for _ in range(3):
                with torch.no_grad():
                    _ = model(inputs)

    def _get_initial_memory(self) -> int:
        """Get initial memory usage before profiling.

        Synchronizes CUDA devices and measures total allocated memory across all GPUs.

        Returns:
            Total memory allocated across all CUDA devices in bytes, or 0 if not available.
        """
        if torch is not None and hasattr(torch, "cuda") and self.gpu_type == "nvidia_cuda":
            torch.cuda.synchronize()
            return sum(torch.cuda.memory_allocated(i) for i in range(self.device_count))
        return 0

    def _profile_single_iteration(self, model: TorchModel, inputs: Any, iteration: int) -> dict[str, object]:
        """Profile a single forward pass iteration.

        Measures memory before/after forward pass and forward execution time.

        Args:
            model: Model to profile.
            inputs: Input data for forward pass.
            iteration: Current iteration number for reporting.

        Returns:
            Dictionary with 'forward_time' (milliseconds) and 'memory_info' containing
            iteration metadata and memory deltas.
        """
        iter_start_memory = self._measure_memory_before_forward()
        forward_time = self._measure_forward_pass(model, inputs)
        iter_end_memory, per_device_memory = self._measure_memory_after_forward()

        return {
            "forward_time": forward_time,
            "memory_info": {
                "iteration": iteration,
                "memory_before": iter_start_memory,
                "memory_after": iter_end_memory,
                "memory_delta": iter_end_memory - iter_start_memory,
                "per_device": per_device_memory,
            },
        }

    def _measure_memory_before_forward(self) -> int:
        """Measure memory usage before forward pass.

        Sums allocated memory across all CUDA devices.

        Returns:
            Total allocated memory in bytes across all devices, or 0 if unavailable.
        """
        if torch is not None and hasattr(torch, "cuda") and self.gpu_type == "nvidia_cuda":
            return sum(torch.cuda.memory_allocated(j) for j in range(self.device_count))
        return 0

    def _measure_forward_pass(self, model: TorchModel, inputs: Any) -> float:
        """Measure forward pass execution time.

        Synchronizes devices, runs forward pass without gradients, and returns elapsed time.

        Args:
            model: Model to run forward pass on.
            inputs: Input data for forward pass.

        Returns:
            Forward pass execution time in milliseconds.
        """
        if not HAS_TORCH or torch is None:
            return 0.0

        self._synchronize_devices()
        start_time = time.time()

        with torch.no_grad():
            _ = model(inputs)

        self._synchronize_devices()
        return (time.time() - start_time) * 1000

    def _synchronize_devices(self) -> None:
        """Synchronize all devices before timing measurements.

        Waits for all GPU operations to complete for accurate timing measurements.
        Supports both NVIDIA CUDA and Intel XPU devices.
        """
        if torch is not None:
            if self.gpu_type == "nvidia_cuda" and hasattr(torch, "cuda"):
                torch.cuda.synchronize()
            elif self.gpu_type == "intel_xpu" and hasattr(torch, "xpu") and hasattr(torch.xpu, "synchronize"):
                torch.xpu.synchronize()

    def _measure_memory_after_forward(self) -> tuple[int, list[int]]:
        """Measure memory usage after forward pass.

        Measures total and per-device memory allocation after forward pass.

        Returns:
            Tuple of (total_memory_bytes, per_device_memory_list) where per_device_memory_list
            contains allocated memory for each CUDA device.
        """
        if torch is not None and hasattr(torch, "cuda") and self.gpu_type == "nvidia_cuda":
            total_memory = sum(torch.cuda.memory_allocated(j) for j in range(self.device_count))
            per_device = [torch.cuda.memory_allocated(j) for j in range(self.device_count)]
            return total_memory, per_device
        return 0, []

    def _get_final_memory(self, start_memory: int) -> tuple[int, int]:
        """Get final and peak memory usage after profiling.

        Measures final allocated and peak memory across all CUDA devices after profiling completes.

        Args:
            start_memory: Initial memory baseline for comparison (not used in calculation).

        Returns:
            Tuple of (end_memory_bytes, peak_memory_bytes) across all devices.
        """
        if torch is not None and hasattr(torch, "cuda") and self.gpu_type == "nvidia_cuda":
            end_memory = sum(torch.cuda.memory_allocated(i) for i in range(self.device_count))
            peak_memory = sum(torch.cuda.max_memory_allocated(i) for i in range(self.device_count))
            return end_memory, peak_memory
        return start_memory, start_memory

    def _compile_profiling_results(
        self,
        device_map: dict[str, object],
        forward_times: list[float],
        memory_usage: list[dict[str, object]],
        start_memory: int,
        end_memory: int,
        peak_memory: int,
    ) -> dict[str, object]:
        """Compile all profiling results into a comprehensive report.

        Aggregates forward timing statistics, memory measurements, and device balance
        score into a single comprehensive profiling report dictionary.

        Args:
            device_map: Device mapping used in profiling.
            forward_times: List of forward pass times in milliseconds.
            memory_usage: List of per-iteration memory info dictionaries.
            start_memory: Initial memory before profiling in bytes.
            end_memory: Final memory after profiling in bytes.
            peak_memory: Peak memory used during profiling in bytes.

        Returns:
            Dictionary containing 'device_map', 'num_devices', 'forward_time_ms',
            'memory_usage_bytes', 'memory_profile', and 'balance_score'.
        """
        avg_time = sum(forward_times) / len(forward_times)
        min_time = min(forward_times)
        max_time = max(forward_times)

        memory_deltas: list[int] = []
        for usage in memory_usage:
            memory_delta_obj = usage.get("memory_delta", 0)
            if isinstance(memory_delta_obj, int):
                memory_deltas.append(memory_delta_obj)

        avg_memory_delta = sum(memory_deltas) / len(memory_deltas) if memory_deltas else 0
        max_memory_delta = max(memory_deltas, default=0)

        results = {
            "device_map": device_map,
            "num_devices": self.device_count,
            "forward_time_ms": {
                "average": avg_time,
                "min": min_time,
                "max": max_time,
                "all": forward_times,
            },
            "memory_usage_bytes": {
                "start": start_memory,
                "end": end_memory,
                "peak": peak_memory,
                "increase": end_memory - start_memory,
            },
            "memory_profile": {
                "per_iteration": memory_usage,
                "avg_delta_per_iteration": avg_memory_delta,
                "max_delta_per_iteration": max_memory_delta,
                "total_iterations": len(memory_usage),
            },
            "balance_score": self.get_device_balance_score(device_map),
        }

        logger.info("Profiling complete - Avg forward time: %.2fms", avg_time)
        return results


# Global instance
_sharding_manager = None


def get_sharding_manager() -> ModelShardingManager:
    """Get or create the global sharding manager instance.

    Returns singleton instance of ModelShardingManager for managing model sharding
    operations across the application. Creates instance on first call.

    Returns:
        Global ModelShardingManager singleton instance.
    """
    global _sharding_manager
    if _sharding_manager is None:
        _sharding_manager = ModelShardingManager()
    return _sharding_manager
