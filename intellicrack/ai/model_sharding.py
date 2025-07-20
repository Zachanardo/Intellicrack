"""
Model Sharding and Distribution Manager

This module provides functionality for distributing large models across multiple GPUs.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import gc
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..utils.logger import get_logger

logger = get_logger(__name__)

# Try importing PyTorch
try:
    import torch
    HAS_TORCH = True

    # Import unified GPU system
    try:
        from ..utils.gpu_autoloader import (
            get_device,
            get_gpu_info,
            gpu_autoloader,
            optimize_for_gpu,
            to_device,
        )
        GPU_AUTOLOADER_AVAILABLE = True
    except ImportError:
        GPU_AUTOLOADER_AVAILABLE = False

except ImportError:
    torch = None
    HAS_TORCH = False
    GPU_AUTOLOADER_AVAILABLE = False

# Try importing accelerate for advanced model parallelism
try:
    from accelerate import (
        Accelerator,
        dispatch_model,
        infer_auto_device_map,
        init_empty_weights,
        load_checkpoint_and_dispatch,
    )
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
    from transformers import (
        AutoConfig,
        AutoModel,
        AutoModelForCausalLM,
    )
    HAS_TRANSFORMERS = True
except ImportError as e:
    logger.error("Import error in model_sharding: %s", e)
    AutoConfig = None
    AutoModel = None
    AutoModelForCausalLM = None
    HAS_TRANSFORMERS = False


class ModelShardingManager:
    """Manages model sharding across multiple GPUs."""

    def __init__(self):
        """Initialize the model sharding manager."""
        # Use unified GPU system if available
        if GPU_AUTOLOADER_AVAILABLE:
            gpu_info = get_gpu_info()
            self.device_count = gpu_info['info'].get('device_count', 0) if gpu_info['available'] else 0
            self.gpu_type = gpu_info['type']
            self.unified_device = get_device()
        else:
            self.device_count = torch.cuda.device_count(
            ) if HAS_TORCH and torch.cuda.is_available() else 0
            self.gpu_type = 'cuda' if self.device_count > 0 else 'cpu'
            self.unified_device = None

        self.device_properties = {}
        self.shard_configs = {}

        if self.device_count > 0 and HAS_TORCH:
            for i in range(self.device_count):
                if self.gpu_type == 'nvidia_cuda':
                    props = torch.cuda.get_device_properties(i)
                    self.device_properties[i] = {
                        "name": props.name,
                        "total_memory": props.total_memory,
                        "major": props.major,
                        "minor": props.minor,
                        "multi_processor_count": props.multi_processor_count,
                    }
                elif self.gpu_type == 'intel_xpu' and hasattr(torch, 'xpu'):
                    # Intel XPU properties
                    self.device_properties[i] = {
                        "name": torch.xpu.get_device_name(i) if hasattr(torch.xpu, 'get_device_name') else f"Intel XPU {i}",
                        "total_memory": 0,  # Will be filled if available
                        "device_type": "xpu"
                    }
                    # Try to get memory info
                    if hasattr(torch.xpu, 'get_device_properties'):
                        try:
                            props = torch.xpu.get_device_properties(i)
                            if hasattr(props, 'total_memory'):
                                self.device_properties[i]["total_memory"] = props.total_memory
                        except (AttributeError, RuntimeError):
                            pass

            logger.info(f"Initialized sharding manager with {self.device_count} {self.gpu_type} devices")
        else:
            logger.info("No GPUs detected, sharding disabled")

    def get_sharding_info(self) -> Dict[str, Any]:
        """Get information about current sharding configuration."""
        info = {
            "available": self.device_count > 1,
            "device_count": self.device_count,
            "devices": self.device_properties,
            "current_device": self._get_current_device(),
            "accelerate_available": HAS_ACCELERATE
        }

        # Add memory info
        if self.device_count > 0 and HAS_TORCH:
            for i in range(self.device_count):
                if self.gpu_type == 'nvidia_cuda':
                    torch.cuda.set_device(i)
                    info["devices"][i]["allocated_memory"] = torch.cuda.memory_allocated(i)
                    info["devices"][i]["reserved_memory"] = torch.cuda.memory_reserved(i)
                    info["devices"][i]["free_memory"] = (
                        info["devices"][i]["total_memory"] -
                        torch.cuda.memory_allocated(i)
                    )
                elif self.gpu_type == 'intel_xpu' and hasattr(torch, 'xpu'):
                    if hasattr(torch.xpu, 'set_device'):
                        torch.xpu.set_device(i)
                    if hasattr(torch.xpu, 'memory_allocated'):
                        info["devices"][i]["allocated_memory"] = torch.xpu.memory_allocated(i)
                    if hasattr(torch.xpu, 'memory_reserved'):
                        info["devices"][i]["reserved_memory"] = torch.xpu.memory_reserved(i)

        return info

    def _get_current_device(self) -> int:
        """Get current device index."""
        if GPU_AUTOLOADER_AVAILABLE and self.unified_device:
            # Extract device index from unified device
            device_str = str(self.unified_device)
            if ':' in device_str:
                return int(device_str.split(':')[1])
            return 0
        elif self.gpu_type == 'nvidia_cuda' and torch.cuda.is_available():
            return torch.cuda.current_device()
        elif self.gpu_type == 'intel_xpu' and hasattr(torch, 'xpu'):
            if hasattr(torch.xpu, 'current_device'):
                return torch.xpu.current_device()
        return 0

    def create_device_map(
        self,
        model_config_or_path: Union[str, Dict],
        max_memory: Optional[Dict[int, str]] = None,
        no_split_module_classes: Optional[List[str]] = None,
        dtype: Optional[torch.dtype] = None
    ) -> Dict[str, Any]:
        """
        Create a device map for model sharding.

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
                    dtype=dtype
                )

            logger.info(f"Created device map: {device_map}")
            return device_map

        except Exception as e:
            logger.error(f"Failed to create device map: {e}")
            return self._create_simple_device_map()

    def _create_simple_device_map(self) -> Dict[str, Any]:
        """Create a simple device map for basic sharding."""
        if self.device_count == 0:
            return {"": "cpu"}
        elif self.device_count == 1:
            return {"": 0}
        else:
            # Simple layer-based distribution
            return {
                "embed_tokens": 0,
                "layers": list(range(self.device_count)),
                "norm": self.device_count - 1,
                "lm_head": self.device_count - 1
            }

    def _get_balanced_memory(self) -> Dict[int, str]:
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
        model: Any,
        device_map: Optional[Dict[str, Any]] = None,
        max_memory: Optional[Dict[int, str]] = None,
        offload_folder: Optional[str] = None,
        offload_state_dict: bool = False
    ) -> Any:
        """
        Shard a model across multiple devices.

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
            logger.warning("Accelerate not available, model not sharded")
            if GPU_AUTOLOADER_AVAILABLE:
                # Apply GPU optimizations before moving to device
                if optimize_for_gpu:
                    optimized = optimize_for_gpu(model)
                    if optimized is not None:
                        model = optimized
                        logger.info("Applied GPU optimizations to model")
                return to_device(model)
            return model

        if self.device_count <= 1:
            logger.info("Single GPU - no sharding needed")
            if GPU_AUTOLOADER_AVAILABLE:
                # Apply GPU optimizations for single GPU
                if optimize_for_gpu:
                    optimized = optimize_for_gpu(model)
                    if optimized is not None:
                        model = optimized
                        logger.info("Applied GPU optimizations to model")
                return to_device(model)
            elif self.device_count == 1:
                return model.to(0) if torch.cuda.is_available() else model
            return model

        # Create device map if not provided
        if device_map is None:
            device_map = self._create_simple_device_map()

        # Apply GPU optimization before sharding
        if GPU_AUTOLOADER_AVAILABLE and optimize_for_gpu:
            try:
                optimized = optimize_for_gpu(model)
                if optimized is not None:
                    model = optimized
                    logger.info("Applied GPU optimizations before sharding")
            except Exception as e:
                logger.debug(f"Could not optimize model before sharding: {e}")

        # Dispatch model
        try:
            model = dispatch_model(
                model,
                device_map=device_map,
                max_memory=max_memory,
                offload_folder=offload_folder,
                offload_state_dict=offload_state_dict
            )
            logger.info("Model successfully sharded across devices")

            # Apply autoloader optimizations after sharding
            if GPU_AUTOLOADER_AVAILABLE and gpu_autoloader:
                try:
                    optimized = gpu_autoloader(model)
                    if optimized is not None:
                        model = optimized
                        logger.info("Applied autoloader optimizations after sharding")
                except Exception as e:
                    logger.debug(f"Could not apply autoloader optimizations: {e}")

            return model

        except Exception as e:
            logger.error(f"Failed to shard model: {e}")
            if GPU_AUTOLOADER_AVAILABLE:
                return to_device(model)
            return model

    def load_sharded_checkpoint(
        self,
        model: Any,
        checkpoint: Union[str, Path],
        device_map: Optional[Dict[str, Any]] = None,
        max_memory: Optional[Dict[int, str]] = None,
        no_split_module_classes: Optional[List[str]] = None,
        dtype: Optional[torch.dtype] = None
    ) -> Any:
        """
        Load a checkpoint and shard it across devices.

        Args:
            model: Model architecture
            checkpoint: Path to checkpoint
            device_map: Custom device map
            max_memory: Maximum memory per device
            no_split_module_classes: Module classes that shouldn't be split
            dtype: Model dtype

        Returns:
            Loaded and sharded model
        """
        if not HAS_ACCELERATE:
            logger.warning("Accelerate not available, loading normally")
            if HAS_TORCH:
                model.load_state_dict(torch.load(checkpoint))
                if GPU_AUTOLOADER_AVAILABLE:
                    # Apply GPU optimizations after loading
                    if optimize_for_gpu:
                        optimized = optimize_for_gpu(model)
                        if optimized is not None:
                            model = optimized
                            logger.info("Applied GPU optimizations to loaded model")
                    return to_device(model)
            return model

        if self.device_count <= 1:
            logger.info("Single GPU - loading normally")
            if HAS_TORCH:
                model.load_state_dict(torch.load(checkpoint))
                if GPU_AUTOLOADER_AVAILABLE:
                    # Apply GPU optimizations for single GPU
                    if optimize_for_gpu:
                        optimized = optimize_for_gpu(model)
                        if optimized is not None:
                            model = optimized
                            logger.info("Applied GPU optimizations to loaded model")
                    return to_device(model)
            return model

        # Create device map if not provided
        if device_map is None:
            device_map = self._create_simple_device_map()

        # Load and dispatch checkpoint
        try:
            model = load_checkpoint_and_dispatch(
                model,
                checkpoint,
                device_map=device_map,
                max_memory=max_memory,
                no_split_module_classes=no_split_module_classes,
                dtype=dtype
            )
            logger.info("Checkpoint loaded and sharded across devices")

            # Apply autoloader optimizations after loading sharded checkpoint
            if GPU_AUTOLOADER_AVAILABLE and gpu_autoloader:
                try:
                    optimized = gpu_autoloader(model)
                    if optimized is not None:
                        model = optimized
                        logger.info("Applied autoloader optimizations to sharded checkpoint")
                except Exception as e:
                    logger.debug(f"Could not apply autoloader optimizations: {e}")

            return model

        except Exception as e:
            logger.error(f"Failed to load sharded checkpoint: {e}")
            if HAS_TORCH:
                model.load_state_dict(torch.load(checkpoint))
                if GPU_AUTOLOADER_AVAILABLE:
                    # Apply optimizations even on fallback
                    if optimize_for_gpu:
                        optimized = optimize_for_gpu(model)
                        if optimized is not None:
                            model = optimized
                    return to_device(model)
            return model

    def estimate_model_memory(
        self,
        model_config: Dict[str, Any],
        dtype: Optional[torch.dtype] = None
    ) -> Dict[str, Any]:
        """
        Estimate memory requirements for a model.

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
                vocab_size * hidden_size +  # Embeddings
                num_layers * 4 * hidden_size * hidden_size +  # Attention
                num_layers * 4 * hidden_size * hidden_size +  # MLP
                2 * num_layers * hidden_size  # Layer norms
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
                    "usage_percent": (memory_per_device / device_memory) * 100
                }

        return {
            "param_count": param_count,
            "model_memory_bytes": model_memory,
            "total_memory_bytes": total_memory,
            "memory_per_device": total_memory // max(self.device_count, 1),
            "device_distribution": device_distribution,
            "fits_in_memory": all(
                d["usage_percent"] < 90 for d in device_distribution.values()
            ) if device_distribution else False
        }

    def optimize_device_map(
        self,
        device_map: Dict[str, Any],
        model_config: Dict[str, Any],
        layer_wise: bool = True
    ) -> Dict[str, Any]:
        """
        Optimize a device map for better performance.

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
            "decoder": {}
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

        logger.info(f"Optimized device map for {num_layers} layers across {self.device_count} devices")
        return optimized_map

    def monitor_memory_usage(self) -> Dict[int, Dict[str, float]]:
        """Monitor memory usage across all devices."""
        memory_info = {}

        if not HAS_TORCH or self.device_count == 0:
            return memory_info

        for i in range(self.device_count):
            if self.gpu_type == 'nvidia_cuda':
                allocated = torch.cuda.memory_allocated(i) / (1024**3)
                reserved = torch.cuda.memory_reserved(i) / (1024**3)
                total = self.device_properties[i]["total_memory"] / (1024**3)

                memory_info[i] = {
                    "allocated_gb": allocated,
                    "reserved_gb": reserved,
                    "free_gb": total - allocated,
                    "total_gb": total,
                    "usage_percent": (allocated / total) * 100
                }
            elif self.gpu_type == 'intel_xpu' and hasattr(torch, 'xpu'):
                memory_info[i] = {"device_type": "xpu", "device_id": i}
                if hasattr(torch.xpu, 'memory_allocated'):
                    allocated = torch.xpu.memory_allocated(i) / (1024**3)
                    memory_info[i]["allocated_gb"] = allocated
                if hasattr(torch.xpu, 'memory_reserved'):
                    reserved = torch.xpu.memory_reserved(i) / (1024**3)
                    memory_info[i]["reserved_gb"] = reserved
                if i in self.device_properties and self.device_properties[i].get("total_memory"):
                    total = self.device_properties[i]["total_memory"] / (1024**3)
                    memory_info[i]["total_gb"] = total
                    if "allocated_gb" in memory_info[i]:
                        memory_info[i]["free_gb"] = total - memory_info[i]["allocated_gb"]
                        memory_info[i]["usage_percent"] = (memory_info[i]["allocated_gb"] / total) * 100

        return memory_info

    def cleanup_memory(self):
        """Clean up GPU memory across all devices."""
        if not HAS_TORCH or self.device_count == 0:
            return

        for i in range(self.device_count):
            if self.gpu_type == 'nvidia_cuda':
                torch.cuda.set_device(i)
                torch.cuda.empty_cache()
            elif self.gpu_type == 'intel_xpu' and hasattr(torch, 'xpu'):
                if hasattr(torch.xpu, 'set_device'):
                    torch.xpu.set_device(i)
                if hasattr(torch.xpu, 'empty_cache'):
                    torch.xpu.empty_cache()

        gc.collect()
        logger.info("Cleaned up memory on all devices")

    def get_device_balance_score(self, device_map: Dict[str, Any]) -> float:
        """
        Calculate balance score for a device map.

        Args:
            device_map: Device mapping

        Returns:
            Balance score (0-1, higher is better)
        """
        if self.device_count <= 1:
            return 1.0

        # Count modules per device
        device_counts = {}
        for _module, device in device_map.items():
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
        balance_score = 1 - (std_dev / max_std_dev) if max_std_dev > 0 else 1.0

        return balance_score

    def create_pipeline_parallel_groups(
        self,
        num_stages: Optional[int] = None
    ) -> List[List[int]]:
        """
        Create process groups for pipeline parallelism.

        Args:
            num_stages: Number of pipeline stages

        Returns:
            List of device groups
        """
        if num_stages is None:
            num_stages = self.device_count

        if num_stages > self.device_count:
            logger.warning(
                f"Requested {num_stages} stages but only {self.device_count} devices available"
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
        model: Any,
        sample_input: Any,
        device_map: Dict[str, Any],
        num_iterations: int = 10
    ) -> Dict[str, Any]:
        """
        Profile model performance with given distribution.

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

        # Warmup
        if GPU_AUTOLOADER_AVAILABLE:
            inputs = to_device(sample_input)
        else:
            device_type = self.gpu_type.split('_')[0] if '_' in self.gpu_type else 'cuda'
            if hasattr(sample_input, 'to') and self.device_count > 0:
                inputs = sample_input.to(device_type)
            else:
                inputs = sample_input

        for _ in range(3):
            with torch.no_grad():
                _ = model(inputs)

        # Profile
        forward_times = []
        memory_usage = []

        if self.gpu_type == 'nvidia_cuda':
            torch.cuda.synchronize()
            start_memory = sum(
                torch.cuda.memory_allocated(i)
                for i in range(self.device_count)
            )
        else:
            start_memory = 0

        for i in range(num_iterations):
            # Measure memory before forward pass
            if self.gpu_type == 'nvidia_cuda':
                iter_start_memory = sum(
                    torch.cuda.memory_allocated(j)
                    for j in range(self.device_count)
                )
            else:
                iter_start_memory = 0

            # Forward pass
            if self.gpu_type == 'nvidia_cuda':
                torch.cuda.synchronize()
            elif self.gpu_type == 'intel_xpu' and hasattr(torch.xpu, 'synchronize'):
                torch.xpu.synchronize()

            start_time = time.time()

            with torch.no_grad():
                _ = model(inputs)

            if self.gpu_type == 'nvidia_cuda':
                torch.cuda.synchronize()
            elif self.gpu_type == 'intel_xpu' and hasattr(torch.xpu, 'synchronize'):
                torch.xpu.synchronize()

            forward_times.append((time.time() - start_time) * 1000)

            # Measure memory after forward pass
            if self.gpu_type == 'nvidia_cuda':
                iter_end_memory = sum(
                    torch.cuda.memory_allocated(j)
                    for j in range(self.device_count)
                )
                memory_usage.append({
                    'iteration': i,
                    'memory_before': iter_start_memory,
                    'memory_after': iter_end_memory,
                    'memory_delta': iter_end_memory - iter_start_memory,
                    'per_device': [
                        torch.cuda.memory_allocated(j)
                        for j in range(self.device_count)
                    ]
                })
            else:
                memory_usage.append({
                    'iteration': i,
                    'memory_before': iter_start_memory,
                    'memory_after': iter_start_memory,
                    'memory_delta': 0,
                    'per_device': []
                })

        # Calculate memory usage
        if self.gpu_type == 'nvidia_cuda':
            end_memory = sum(
                torch.cuda.memory_allocated(i)
                for i in range(self.device_count)
            )
            peak_memory = sum(
                torch.cuda.max_memory_allocated(i)
                for i in range(self.device_count)
            )
        else:
            end_memory = start_memory
            peak_memory = start_memory

        # Calculate statistics
        avg_time = sum(forward_times) / len(forward_times)
        min_time = min(forward_times)
        max_time = max(forward_times)

        # Calculate memory usage statistics
        memory_deltas = [usage['memory_delta'] for usage in memory_usage]
        avg_memory_delta = sum(memory_deltas) / len(memory_deltas) if memory_deltas else 0
        max_memory_delta = max(memory_deltas) if memory_deltas else 0

        results = {
            "device_map": device_map,
            "num_devices": self.device_count,
            "forward_time_ms": {
                "average": avg_time,
                "min": min_time,
                "max": max_time,
                "all": forward_times
            },
            "memory_usage_bytes": {
                "start": start_memory,
                "end": end_memory,
                "peak": peak_memory,
                "increase": end_memory - start_memory
            },
            "memory_profile": {
                "per_iteration": memory_usage,
                "avg_delta_per_iteration": avg_memory_delta,
                "max_delta_per_iteration": max_memory_delta,
                "total_iterations": len(memory_usage)
            },
            "balance_score": self.get_device_balance_score(device_map)
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
