"""Model Sharding and Distribution Manager.

This module provides functionality for distributing large models across multiple GPUs.

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

import gc
import time
from pathlib import Path
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import torch
    from torch import nn

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
    logger.error("Import error in model_sharding: %s", e)
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
    logger.error("Import error in model_sharding: %s", e)
    AutoConfig = None
    AutoModel = None
    AutoModelForCausalLM = None
    HAS_TRANSFORMERS = False


class ModelShardingManager:
    """Manages model sharding across multiple GPUs."""

    def __init__(self) -> None:
        """Initialize the model sharding manager."""
        self._initialize_gpu_info()
        self.device_properties = {}
        self.shard_configs = {}

        if self.device_count > 0 and HAS_TORCH:
            self._initialize_device_properties()
            logger.info(
                f"Initialized sharding manager with {self.device_count} {self.gpu_type} devices"
            )
        else:
            logger.info("No GPUs detected, sharding disabled")

    def _initialize_gpu_info(self) -> None:
        """Initialize GPU device information."""
        if GPU_AUTOLOADER_AVAILABLE:
            gpu_info = get_gpu_info()
            self.device_count = (
                gpu_info["info"].get("device_count", 0) if gpu_info["available"] else 0
            )
            self.gpu_type = gpu_info["type"]
            self.unified_device = get_device()
        else:
            self.device_count = (
                torch.cuda.device_count() if HAS_TORCH and torch.cuda.is_available() else 0
            )
            self.gpu_type = "cuda" if self.device_count > 0 else "cpu"
            self.unified_device = None

    def _initialize_device_properties(self) -> None:
        """Initialize properties for all available devices."""
        for i in range(self.device_count):
            if self.gpu_type == "nvidia_cuda":
                self._initialize_nvidia_device_properties(i)
            elif self.gpu_type == "intel_xpu" and hasattr(torch, "xpu"):
                self._initialize_intel_xpu_device_properties(i)

    def _initialize_nvidia_device_properties(self, device_id: int) -> None:
        """Initialize NVIDIA CUDA device properties."""
        props = torch.cuda.get_device_properties(device_id)
        self.device_properties[device_id] = {
            "name": props.name,
            "total_memory": props.total_memory,
            "major": props.major,
            "minor": props.minor,
            "multi_processor_count": props.multi_processor_count,
        }

    def _initialize_intel_xpu_device_properties(self, device_id: int) -> None:
        """Initialize Intel XPU device properties."""
        self.device_properties[device_id] = {
            "name": torch.xpu.get_device_name(device_id)
            if hasattr(torch.xpu, "get_device_name")
            else f"Intel XPU {device_id}",
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
        """Get information about current sharding configuration."""
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
        """Add memory information to device info."""
        for i in range(self.device_count):
            if self.gpu_type == "nvidia_cuda":
                self._add_nvidia_memory_info(info, i)
            elif self.gpu_type == "intel_xpu" and hasattr(torch, "xpu"):
                self._add_intel_xpu_memory_info(info, i)

    def _add_nvidia_memory_info(self, info: dict[str, object], device_id: int) -> None:
        """Add NVIDIA CUDA memory information to device info."""
        torch.cuda.set_device(device_id)
        info["devices"][device_id]["allocated_memory"] = torch.cuda.memory_allocated(device_id)
        info["devices"][device_id]["reserved_memory"] = torch.cuda.memory_reserved(device_id)
        info["devices"][device_id]["free_memory"] = info["devices"][device_id][
            "total_memory"
        ] - torch.cuda.memory_allocated(device_id)

    def _add_intel_xpu_memory_info(self, info: dict[str, object], device_id: int) -> None:
        """Add Intel XPU memory information to device info."""
        if hasattr(torch.xpu, "set_device"):
            torch.xpu.set_device(device_id)
        if hasattr(torch.xpu, "memory_allocated"):
            info["devices"][device_id]["allocated_memory"] = torch.xpu.memory_allocated(device_id)
        if hasattr(torch.xpu, "memory_reserved"):
            info["devices"][device_id]["reserved_memory"] = torch.xpu.memory_reserved(device_id)

    def _get_current_device(self) -> int:
        """Get current device index."""
        if GPU_AUTOLOADER_AVAILABLE and self.unified_device:
            # Extract device index from unified device
            device_str = str(self.unified_device)
            return int(device_str.split(":")[1]) if ":" in device_str else 0
        if self.gpu_type == "nvidia_cuda" and torch.cuda.is_available():
            return torch.cuda.current_device()
        if self.gpu_type == "intel_xpu" and hasattr(torch, "xpu") and hasattr(torch.xpu, "current_device"):
            return torch.xpu.current_device()
        return 0

    def create_device_map(
        self,
        model_config_or_path: str | dict,
        max_memory: dict[int, str] | None = None,
        no_split_module_classes: list[str] | None = None,
        dtype: TorchDtype | None = None,
    ) -> dict[str, object]:
        """Create a device map for model sharding.

        Args:
            model_config_or_path: Model configuration or path
            max_memory: Maximum memory per device
            no_split_module_classes: Module classes that shouldn't be split
            dtype: Model dtype

        Returns:
            Device map for model distribution

        """
        if not HAS_ACCELERATE:
            logger.warning("Accelerate not available, using simple device map")
            return self._create_simple_device_map()

        if self.device_count <= 1:
            return {"": 0} if self.device_count == 1 else {"": "cpu"}

        # Load model config if path provided
        if isinstance(model_config_or_path, str) and HAS_TRANSFORMERS:
            config = AutoConfig.from_pretrained(model_config_or_path)
        else:
            config = model_config_or_path

        # Set default max memory if not provided
        if max_memory is None:
            max_memory = self._get_balanced_memory()

        # Create device map using accelerate
        try:
            with init_empty_weights():
                # Create empty model for device map inference
                if HAS_TRANSFORMERS:
                    model = AutoModelForCausalLM.from_config(config)
                else:
                    logger.warning("Transformers not available")
                    return self._create_simple_device_map()

                device_map = infer_auto_device_map(
                    model,
                    max_memory=max_memory,
                    no_split_module_classes=no_split_module_classes,
                    dtype=dtype,
                )

            logger.info(f"Created device map: {device_map}")
            return device_map

        except Exception as e:
            logger.error(f"Failed to create device map: {e}")
            return self._create_simple_device_map()

    def _create_simple_device_map(self) -> dict[str, object]:
        """Create a simple device map for basic sharding."""
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
        """Get balanced memory allocation across devices."""
        if self.device_count == 0:
            return {}

        max_memory = {}
        for i in range(self.device_count):
            if i in self.device_properties:
                # Reserve 10% for overhead
                total_memory = self.device_properties[i]["total_memory"]
                usable_memory = int(total_memory * 0.9)
                max_memory[i] = f"{usable_memory}B"
            else:
                # Default to 20GB if can't determine
                max_memory[i] = "20GB"

        logger.info(f"Balanced memory allocation: {max_memory}")
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

        Args:
            model: Model to shard
            device_map: Custom device map
            max_memory: Maximum memory per device
            offload_folder: Folder for offloading
            offload_state_dict: Whether to offload state dict

        Returns:
            Sharded model

        """
        if not HAS_ACCELERATE:
            return self._shard_model_without_accelerate(model)

        if self.device_count <= 1:
            return self._shard_model_single_device(model)

        if device_map is None:
            device_map = self._create_simple_device_map()

        model = self._apply_pre_sharding_optimizations(model)

        return self._dispatch_model_across_devices(
            model, device_map, max_memory, offload_folder, offload_state_dict
        )

    def _shard_model_without_accelerate(self, model: TorchModel) -> TorchModel:
        """Shard model without accelerate library."""
        logger.warning("Accelerate not available, model not sharded")
        if GPU_AUTOLOADER_AVAILABLE:
            if optimize_for_gpu:
                optimized = optimize_for_gpu(model)
                if optimized is not None:
                    model = optimized
                    logger.info(APPLIED_GPU_OPTIMIZATIONS_MSG)
            return to_device(model)
        return model

    def _shard_model_single_device(self, model: TorchModel) -> TorchModel:
        """Shard model for single device."""
        logger.info("Single GPU - no sharding needed")
        if GPU_AUTOLOADER_AVAILABLE:
            if optimize_for_gpu:
                optimized = optimize_for_gpu(model)
                if optimized is not None:
                    model = optimized
                    logger.info(APPLIED_GPU_OPTIMIZATIONS_MSG)
            return to_device(model)
        if self.device_count == 1:
            return model.to(0) if torch.cuda.is_available() else model
        return model

    def _apply_pre_sharding_optimizations(self, model: TorchModel) -> TorchModel:
        """Apply optimizations before sharding."""
        if GPU_AUTOLOADER_AVAILABLE and optimize_for_gpu:
            try:
                optimized = optimize_for_gpu(model)
                if optimized is not None:
                    model = optimized
                    logger.info("Applied GPU optimizations before sharding")
            except Exception as e:
                logger.debug(f"Could not optimize model before sharding: {e}")
        return model

    def _dispatch_model_across_devices(
        self,
        model: TorchModel,
        device_map: dict[str, object],
        max_memory: dict[int, str] | None,
        offload_folder: str | None,
        offload_state_dict: bool,
    ) -> TorchModel:
        """Dispatch model across multiple devices."""
        try:
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
            logger.error(f"Failed to shard model: {e}")
            return to_device(model) if GPU_AUTOLOADER_AVAILABLE else model

    def _apply_post_sharding_optimizations(self, model: TorchModel) -> TorchModel:
        """Apply optimizations after sharding."""
        if GPU_AUTOLOADER_AVAILABLE and gpu_autoloader:
            try:
                optimized = gpu_autoloader(model)
                if optimized is not None:
                    model = optimized
                    logger.info("Applied autoloader optimizations after sharding")
            except Exception as e:
                logger.debug(f"Could not apply autoloader optimizations: {e}")
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
        """Load a checkpoint and shard it across devices."""
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

    def _load_checkpoint_without_accelerate(
        self, model: TorchModel, checkpoint: str | Path
    ) -> TorchModel:
        """Load checkpoint without accelerate."""
        logger.warning("Accelerate not available, loading normally")
        if HAS_TORCH:
            model.load_state_dict(torch.load(checkpoint))
            return self._apply_gpu_optimizations(model)
        return model

    def _load_checkpoint_single_device(
        self, model: TorchModel, checkpoint: str | Path
    ) -> TorchModel:
        """Load checkpoint for a single device."""
        logger.info("Single GPU - loading normally")
        if HAS_TORCH:
            model.load_state_dict(torch.load(checkpoint))
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
        """Load and dispatch checkpoint across devices."""
        try:
            model = load_checkpoint_and_dispatch(
                model,
                checkpoint,
                device_map=device_map,
                max_memory=max_memory,
                no_split_module_classes=no_split_module_classes,
                dtype=dtype,
            )
            logger.info("Checkpoint loaded and sharded across devices")
            return self._apply_autoloader_optimizations(model)
        except Exception as e:
            logger.error(f"Failed to load sharded checkpoint: {e}")
            return self._fallback_checkpoint_load(model, checkpoint)

    def _apply_gpu_optimizations(self, model: TorchModel) -> TorchModel:
        """Apply GPU optimizations to the model."""
        if GPU_AUTOLOADER_AVAILABLE and optimize_for_gpu:
            try:
                optimized = optimize_for_gpu(model)
                if optimized is not None:
                    model = optimized
                    logger.info(APPLIED_GPU_OPTIMIZATIONS_MSG)
            except Exception as e:
                logger.debug(f"Could not optimize model: {e}")
        return to_device(model) if GPU_AUTOLOADER_AVAILABLE else model

    def _apply_autoloader_optimizations(self, model: TorchModel) -> TorchModel:
        """Apply autoloader optimizations after sharding."""
        if GPU_AUTOLOADER_AVAILABLE and gpu_autoloader:
            try:
                optimized = gpu_autoloader(model)
                if optimized is not None:
                    model = optimized
                    logger.info("Applied autoloader optimizations to sharded checkpoint")
            except Exception as e:
                logger.debug(f"Could not apply autoloader optimizations: {e}")
        return model

    def _fallback_checkpoint_load(self, model: TorchModel, checkpoint: str | Path) -> TorchModel:
        """Fallback checkpoint loading in case of failure."""
        if HAS_TORCH:
            model.load_state_dict(torch.load(checkpoint))
            return self._apply_gpu_optimizations(model)
        return model

    def estimate_model_memory(
        self,
        model_config: dict[str, object],
        dtype: TorchDtype | None = None,
    ) -> dict[str, object]:
        """Estimate memory requirements for a model.

        Args:
            model_config: Model configuration
            dtype: Model dtype

        Returns:
            Memory estimation details

        """
        if dtype is None and HAS_TORCH:
            dtype = torch.float16

        # Estimate based on parameters
        param_count = model_config.get("num_parameters", 0)
        if param_count == 0:
            # Try to estimate from config
            hidden_size = model_config.get("hidden_size", 4096)
            num_layers = model_config.get("num_hidden_layers", 32)
            vocab_size = model_config.get("vocab_size", 32000)

            # Rough estimation
            param_count = (
                vocab_size * hidden_size  # Embeddings
                + num_layers * 4 * hidden_size * hidden_size  # Attention
                + num_layers * 4 * hidden_size * hidden_size  # MLP
                + 2 * num_layers * hidden_size  # Layer norms
            )

        # Calculate memory based on dtype
        bytes_per_param = 2 if dtype == torch.float16 else 4
        model_memory = param_count * bytes_per_param

        # Add overhead (typically 20-30%)
        total_memory = int(model_memory * 1.25)

        # Calculate optimal sharding
        device_distribution = {}
        if self.device_count > 0:
            memory_per_device = total_memory // self.device_count
            for i in range(self.device_count):
                device_memory = self.device_properties[i]["total_memory"]
                device_distribution[i] = {
                    "allocated": memory_per_device,
                    "available": device_memory,
                    "usage_percent": (memory_per_device / device_memory) * 100,
                }

        return {
            "param_count": param_count,
            "model_memory_bytes": model_memory,
            "total_memory_bytes": total_memory,
            "memory_per_device": total_memory // max(self.device_count, 1),
            "device_distribution": device_distribution,
            "fits_in_memory": all(d["usage_percent"] < 90 for d in device_distribution.values())
            if device_distribution
            else False,
        }

    def optimize_device_map(
        self,
        device_map: dict[str, object],
        model_config: dict[str, object],
        layer_wise: bool = True,
    ) -> dict[str, object]:
        """Optimize a device map for better performance.

        Args:
            device_map: Initial device map
            model_config: Model configuration
            layer_wise: Whether to optimize layer-wise

        Returns:
            Optimized device map

        """
        if not layer_wise or self.device_count <= 1:
            return device_map

        # Get layer configuration
        num_layers = model_config.get("num_hidden_layers", 32)
        layers_per_device = num_layers // self.device_count
        remainder = num_layers % self.device_count

        # Create optimized map
        optimized_map = {
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
                optimized_map["encoder"][f"layer.{layer}"] = device
                optimized_map["decoder"][f"layer.{layer}"] = device

            current_layer += device_layers

        # Put final layers on last device
        last_device = self.device_count - 1
        optimized_map["pooler"] = last_device
        optimized_map["lm_head"] = last_device

        logger.info(
            f"Optimized device map for {num_layers} layers across {self.device_count} devices"
        )
        return optimized_map

    def monitor_memory_usage(self) -> dict[int, dict[str, object]]:
        """Monitor memory usage across all devices."""
        memory_info = {}

        if not HAS_TORCH or self.device_count == 0:
            return memory_info

        for i in range(self.device_count):
            if self.gpu_type == "nvidia_cuda":
                memory_info[i] = self._get_nvidia_memory_usage(i)
            elif self.gpu_type == "intel_xpu" and hasattr(torch, "xpu"):
                memory_info[i] = self._get_intel_xpu_memory_usage(i)

        return memory_info

    def _get_nvidia_memory_usage(self, device_id: int) -> dict[str, object]:
        """Get NVIDIA CUDA memory usage for a device."""
        allocated = torch.cuda.memory_allocated(device_id) / (1024**3)
        reserved = torch.cuda.memory_reserved(device_id) / (1024**3)
        total = self.device_properties[device_id]["total_memory"] / (1024**3)

        return {
            "allocated_gb": allocated,
            "reserved_gb": reserved,
            "free_gb": total - allocated,
            "total_gb": total,
            "usage_percent": (allocated / total) * 100,
        }

    def _get_intel_xpu_memory_usage(self, device_id: int) -> dict[str, object]:
        """Get Intel XPU memory usage for a device."""
        memory_info = {"device_type": "xpu", "device_id": device_id}

        if hasattr(torch.xpu, "memory_allocated"):
            allocated = torch.xpu.memory_allocated(device_id) / (1024**3)
            memory_info["allocated_gb"] = allocated

        if hasattr(torch.xpu, "memory_reserved"):
            reserved = torch.xpu.memory_reserved(device_id) / (1024**3)
            memory_info["reserved_gb"] = reserved

        if device_id in self.device_properties and self.device_properties[device_id].get(
            "total_memory"
        ):
            total = self.device_properties[device_id]["total_memory"] / (1024**3)
            memory_info["total_gb"] = total
            if "allocated_gb" in memory_info:
                memory_info["free_gb"] = total - memory_info["allocated_gb"]
                memory_info["usage_percent"] = (memory_info["allocated_gb"] / total) * 100

        return memory_info

    def cleanup_memory(self) -> None:
        """Clean up GPU memory across all devices."""
        if not HAS_TORCH or self.device_count == 0:
            return

        for i in range(self.device_count):
            if self.gpu_type == "nvidia_cuda":
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

        Args:
            device_map: Device mapping

        Returns:
            Balance score (0-1, higher is better)

        """
        if self.device_count <= 1:
            return 1.0

        # Count modules per device
        device_counts = {}
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

        Args:
            num_stages: Number of pipeline stages

        Returns:
            List of device groups

        """
        if num_stages is None:
            num_stages = self.device_count

        if num_stages > self.device_count:
            logger.warning(
                f"Requested {num_stages} stages but only {self.device_count} devices available",
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

        logger.info(f"Created {len(groups)} pipeline parallel groups: {groups}")
        return groups

    def profile_model_distribution(
        self,
        model: TorchModel,
        sample_input: TorchTensor,
        device_map: dict[str, object],
        num_iterations: int = 10,
    ) -> dict[str, object]:
        """Profile model performance with given distribution.

        Args:
            model: Distributed model
            sample_input: Sample input for profiling
            device_map: Device distribution map
            num_iterations: Number of profiling iterations

        Returns:
            Profiling results

        """
        if not HAS_TORCH:
            logger.error("PyTorch required for profiling")
            return {}

        logger.info(f"Profiling model distribution over {num_iterations} iterations")

        inputs = self._prepare_inputs_for_profiling(sample_input)
        self._warmup_model(model, inputs)

        forward_times = []
        memory_usage = []
        start_memory = self._get_initial_memory()

        for i in range(num_iterations):
            iteration_results = self._profile_single_iteration(model, inputs, i)
            forward_times.append(iteration_results["forward_time"])
            memory_usage.append(iteration_results["memory_info"])

        end_memory, peak_memory = self._get_final_memory(start_memory)

        return self._compile_profiling_results(
            device_map,
            forward_times,
            memory_usage,
            start_memory,
            end_memory,
            peak_memory,
        )

    def _prepare_inputs_for_profiling(self, sample_input: TorchTensor) -> TorchTensor:
        """Prepare inputs for profiling by moving to appropriate device."""
        if GPU_AUTOLOADER_AVAILABLE:
            return to_device(sample_input)
        device_type = self.gpu_type.split("_")[0] if "_" in self.gpu_type else "cuda"
        if hasattr(sample_input, "to") and self.device_count > 0:
            return sample_input.to(device_type)
        return sample_input

    def _warmup_model(self, model: TorchModel, inputs: TorchTensor) -> None:
        """Warmup model with a few iterations."""
        for _ in range(3):
            with torch.no_grad():
                _ = model(inputs)

    def _get_initial_memory(self) -> int:
        """Get initial memory usage before profiling."""
        if self.gpu_type == "nvidia_cuda":
            torch.cuda.synchronize()
            return sum(torch.cuda.memory_allocated(i) for i in range(self.device_count))
        return 0

    def _profile_single_iteration(
        self, model: TorchModel, inputs: TorchTensor, iteration: int
    ) -> dict[str, object]:
        """Profile a single forward pass iteration."""
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
        """Measure memory usage before forward pass."""
        if self.gpu_type == "nvidia_cuda":
            return sum(torch.cuda.memory_allocated(j) for j in range(self.device_count))
        return 0

    def _measure_forward_pass(self, model: TorchModel, inputs: TorchTensor) -> float:
        """Measure forward pass execution time."""
        self._synchronize_devices()
        start_time = time.time()

        with torch.no_grad():
            _ = model(inputs)

        self._synchronize_devices()
        return (time.time() - start_time) * 1000

    def _synchronize_devices(self) -> None:
        """Synchronize all devices before timing measurements."""
        if self.gpu_type == "nvidia_cuda":
            torch.cuda.synchronize()
        elif self.gpu_type == "intel_xpu" and hasattr(torch.xpu, "synchronize"):
            torch.xpu.synchronize()

    def _measure_memory_after_forward(self) -> tuple[int, list[int]]:
        """Measure memory usage after forward pass."""
        if self.gpu_type == "nvidia_cuda":
            total_memory = sum(torch.cuda.memory_allocated(j) for j in range(self.device_count))
            per_device = [torch.cuda.memory_allocated(j) for j in range(self.device_count)]
            return total_memory, per_device
        return 0, []

    def _get_final_memory(self, start_memory: int) -> tuple[int, int]:
        """Get final and peak memory usage after profiling."""
        if self.gpu_type == "nvidia_cuda":
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
        """Compile all profiling results into a comprehensive report."""
        avg_time = sum(forward_times) / len(forward_times)
        min_time = min(forward_times)
        max_time = max(forward_times)

        memory_deltas = [usage["memory_delta"] for usage in memory_usage]
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

        logger.info(f"Profiling complete - Avg forward time: {avg_time:.2f}ms")
        return results


# Global instance
_sharding_manager = None


def get_sharding_manager() -> ModelShardingManager:
    """Get or create the global sharding manager instance."""
    global _sharding_manager
    if _sharding_manager is None:
        _sharding_manager = ModelShardingManager()
    return _sharding_manager
