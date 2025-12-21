"""Model Quantization Manager for Intellicrack.

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
from pathlib import Path
from typing import Any, TypeVar, cast

from ..utils.logger import get_logger
from .model_sharding import get_sharding_manager


ModelType = TypeVar("ModelType")
ConfigType = TypeVar("ConfigType")

try:
    import torch
    from torch.nn import Module

    HAS_TORCH = True

    # Import unified GPU system
    try:
        from ..utils.gpu_autoloader import get_device, get_gpu_info, gpu_autoloader, optimize_for_gpu, to_device

        GPU_AUTOLOADER_AVAILABLE = True
    except ImportError:
        GPU_AUTOLOADER_AVAILABLE = False

except ImportError:
    torch = None  # type: ignore[assignment]
    Module = Any  # type: ignore[misc,assignment]
    HAS_TORCH = False
    GPU_AUTOLOADER_AVAILABLE = False


logger = get_logger(__name__)

# Try to import quantization libraries
try:
    import bitsandbytes as bnb

    HAS_BITSANDBYTES = True
except (ImportError, AttributeError) as e:
    # AttributeError can occur if bitsandbytes has internal import issues
    logger.debug("Optional dependency bitsandbytes not available: %s", e)
    bnb = None  # type: ignore[assignment]
    HAS_BITSANDBYTES = False
except Exception as e:
    # Catch any other errors from bitsandbytes initialization
    logger.debug("Error initializing bitsandbytes: %s", e)
    bnb = None  # type: ignore[assignment]
    HAS_BITSANDBYTES = False

try:
    from auto_gptq import AutoGPTQForCausalLM, BaseQuantizeConfig

    HAS_AUTO_GPTQ = True
except ImportError as e:
    logger.debug("Optional dependency auto_gptq not available: %s", e)
    AutoGPTQForCausalLM = None
    BaseQuantizeConfig = None
    HAS_AUTO_GPTQ = False

# AWQ removed due to dependency issues
HAS_AWQ = False
AutoAWQForCausalLM: Any = None

try:
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, GPTQConfig

    HAS_TRANSFORMERS = True
except ImportError as e:
    logger.exception("Import error in quantization_manager: %s", e)
    AutoModelForCausalLM = None  # type: ignore[assignment,misc]
    AutoTokenizer = None  # type: ignore[assignment,misc]
    BitsAndBytesConfig = None  # type: ignore[assignment,misc]
    GPTQConfig = None  # type: ignore[assignment,misc]
    HAS_TRANSFORMERS = False

try:
    from peft import LoraConfig, PeftModel, get_peft_model, prepare_model_for_kbit_training

    HAS_PEFT = True
except ImportError as e:
    logger.exception("Import error in quantization_manager: %s", e)
    PeftModel = None  # type: ignore[assignment,misc]
    LoraConfig = None  # type: ignore[assignment,misc]
    get_peft_model = None  # type: ignore[assignment]
    prepare_model_for_kbit_training = None  # type: ignore[assignment]
    HAS_PEFT = False


class QuantizationManager:
    """Manages model quantization for efficient inference."""

    def __init__(self) -> None:
        """Initialize the quantization manager."""
        self.loaded_models: dict[str, Any] = {}
        self.quantization_configs: dict[str, dict[str, object]] = {}
        self.sharding_manager: Any = None

        # Check available backends
        self.available_backends: dict[str, bool] = {
            "bitsandbytes": HAS_BITSANDBYTES,
            "auto_gptq": HAS_AUTO_GPTQ,
            "transformers": HAS_TRANSFORMERS,
            "peft": HAS_PEFT,
        }

        logger.info("Quantization backends available: %s", self.available_backends)

        # Initialize sharding manager if multi-GPU available
        if GPU_AUTOLOADER_AVAILABLE:
            gpu_info = get_gpu_info()
            if isinstance(gpu_info, dict) and gpu_info.get("available") and isinstance(gpu_info.get("info"), dict):
                info_dict = cast("dict[str, Any]", gpu_info["info"])
                device_count = info_dict.get("device_count", 1)
                if isinstance(device_count, int) and device_count > 1:
                    self.sharding_manager = get_sharding_manager()
                    logger.info("Multi-GPU sharding enabled with %d devices", device_count)
        elif HAS_TORCH and torch is not None and torch.cuda.device_count() > 1:
            self.sharding_manager = get_sharding_manager()
            logger.info("Multi-GPU sharding enabled with %d devices", torch.cuda.device_count())

    def load_quantized_model(
        self,
        model_path: str | Path,
        quantization_type: str = "auto",
        device: str = "auto",
        **kwargs: object,
    ) -> Any:
        """Load a quantized model with automatic backend selection.

        Args:
            model_path: Path to model file or directory
            quantization_type: Type of quantization ("auto", "8bit", "4bit", "gptq")
            device: Device to load model on ("auto", "cpu", "cuda", "mps")
            **kwargs: Additional arguments for model loading

        Returns:
            Loaded model or None on failure

        """
        model_path = Path(model_path)

        # Auto-detect device
        if device == "auto":
            device = self._get_best_device()

        # Auto-detect quantization type
        if quantization_type == "auto":
            quantization_type = self._detect_quantization_type(model_path)

        logger.info("Loading model with %s quantization on %s", quantization_type, device)

        try:
            if quantization_type == "8bit":
                return self._load_8bit_model(model_path, device, **kwargs)
            if quantization_type == "4bit":
                return self._load_4bit_model(model_path, device, **kwargs)
            if quantization_type == "gptq":
                return self._load_gptq_model(model_path, device, **kwargs)
            if quantization_type == "awq":
                logger.warning("AWQ support has been removed due to dependency issues")
                return None
            # Load without quantization
            return self._load_standard_model(model_path, device, **kwargs)

        except Exception as e:
            logger.exception("Failed to load quantized model: %s", e)
            return None

    def _get_best_device(self) -> str:
        """Get the best available device for model loading."""
        if GPU_AUTOLOADER_AVAILABLE:
            device_result = get_device()
            return device_result if isinstance(device_result, str) else "cpu"
        if HAS_TORCH and torch is not None:
            if torch.cuda.is_available():
                return "cuda"
            if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return "mps"
        return "cpu"

    def _detect_quantization_type(self, model_path: Path) -> str:
        """Detect quantization type from model files."""
        # Check for GPTQ files
        if model_path.is_dir():
            files = list(model_path.glob("*.safetensors")) + list(model_path.glob("*.bin"))
            for file in files:
                if "gptq" in file.name.lower():
                    return "gptq"

        # Check config file
        config_path = model_path / "config.json" if model_path.is_dir() else None
        if config_path and config_path.exists():
            import json

            with open(config_path) as f:
                config = json.load(f)
                if "quantization_config" in config:
                    quant_config = config["quantization_config"]
                    if "bits" in quant_config:
                        return f"{quant_config['bits']}bit"
                    if quant_config.get("quant_method") == "gptq":
                        return "gptq"

        return "none"

    def _load_8bit_model(self, model_path: Path, device: str, **kwargs: object) -> Any:
        """Load model with 8-bit quantization using bitsandbytes."""
        if not HAS_BITSANDBYTES or not HAS_TRANSFORMERS or BitsAndBytesConfig is None or AutoModelForCausalLM is None or torch is None:
            logger.exception("bitsandbytes, transformers, and PyTorch required for 8-bit quantization")
            return None

        if device == "cpu":
            logger.exception("8-bit quantization requires CUDA device")
            return None

        try:
            # Configure 8-bit quantization
            quantization_config: Any = BitsAndBytesConfig(  # type: ignore[no-untyped-call]
                load_in_8bit=True,
                bnb_8bit_compute_dtype=torch.float16,
                bnb_8bit_use_double_quant=True,
                bnb_8bit_quant_type="nf4",
            )

            # Check if multi-GPU sharding should be used
            device_map: str | dict[str, Any] = "auto"
            if self.sharding_manager and kwargs.get("enable_sharding", True):
                device_map = cast(
                    "dict[str, Any]",
                    self.sharding_manager.create_device_map(
                        model_path,
                        max_memory=kwargs.get("max_memory"),
                        no_split_module_classes=kwargs.get("no_split_module_classes"),
                    ),
                )

            # Load model
            model = AutoModelForCausalLM.from_pretrained(
                str(model_path),
                quantization_config=quantization_config,
                device_map=device_map,
                trust_remote_code=kwargs.get("trust_remote_code", True),
                torch_dtype=torch.float16,
            )

            logger.info("Successfully loaded 8-bit quantized model")
            return cast("Any", model)

        except Exception as e:
            logger.exception("Failed to load 8-bit model: %s", e)
            return None

    def _load_4bit_model(self, model_path: Path, device: str, **kwargs: object) -> Any:
        """Load model with 4-bit quantization using bitsandbytes."""
        if not HAS_BITSANDBYTES or not HAS_TRANSFORMERS or BitsAndBytesConfig is None or AutoModelForCausalLM is None or torch is None:
            logger.exception("bitsandbytes, transformers, and PyTorch required for 4-bit quantization")
            return None

        if device == "cpu":
            logger.exception("4-bit quantization requires CUDA device")
            return None

        try:
            # Configure 4-bit quantization
            quantization_config: Any = BitsAndBytesConfig(  # type: ignore[no-untyped-call]
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",
            )

            # Check if multi-GPU sharding should be used
            device_map: str | dict[str, Any] = "auto"
            if self.sharding_manager and kwargs.get("enable_sharding", True):
                device_map = cast(
                    "dict[str, Any]",
                    self.sharding_manager.create_device_map(
                        model_path,
                        max_memory=kwargs.get("max_memory"),
                        no_split_module_classes=kwargs.get("no_split_module_classes"),
                    ),
                )

            # Load model
            model = AutoModelForCausalLM.from_pretrained(
                str(model_path),
                quantization_config=quantization_config,
                device_map=device_map,
                trust_remote_code=kwargs.get("trust_remote_code", True),
                torch_dtype=torch.float16,
            )

            # Prepare for training if needed
            if kwargs.get("prepare_for_training") and HAS_PEFT and prepare_model_for_kbit_training is not None:
                model = prepare_model_for_kbit_training(model)  # type: ignore[no-untyped-call]

            logger.info("Successfully loaded 4-bit quantized model")
            return cast("Any", model)

        except Exception as e:
            logger.exception("Failed to load 4-bit model: %s", e)
            return None

    def _load_gptq_model(self, model_path: Path, device: str, **kwargs: object) -> Any:
        """Load GPTQ quantized model."""
        if not HAS_AUTO_GPTQ or AutoGPTQForCausalLM is None:
            logger.exception("auto-gptq required for GPTQ models")
            return None

        if device == "cpu":
            logger.exception("GPTQ models require CUDA device")
            return None

        try:
            # Load model
            fused_attention = kwargs.get("fused_attention", True)
            fused_mlp = kwargs.get("fused_mlp", True)
            trust_remote = kwargs.get("trust_remote_code", True)

            model = AutoGPTQForCausalLM.from_quantized(
                str(model_path),
                device_map="auto",
                trust_remote_code=trust_remote if isinstance(trust_remote, bool) else True,
                use_safetensors=True,
                inject_fused_attention=fused_attention if isinstance(fused_attention, bool) else True,
                inject_fused_mlp=fused_mlp if isinstance(fused_mlp, bool) else True,
            )

            logger.info("Successfully loaded GPTQ model")
            return cast("Any", model)

        except Exception as e:
            logger.exception("Failed to load GPTQ model: %s", e)
            return None

    def _load_standard_model(self, model_path: Path, device: str, **kwargs: object) -> Any:
        """Load model without quantization."""
        if not HAS_TRANSFORMERS or AutoModelForCausalLM is None or torch is None:
            logger.exception("transformers and PyTorch required for model loading")
            return None

        try:
            # Determine torch dtype
            torch_dtype_param = kwargs.get("torch_dtype", "auto")
            torch_dtype: Any = torch_dtype_param
            if torch_dtype == "auto":
                torch_dtype = torch.float16 if device != "cpu" else torch.float32

            # Check if multi-GPU sharding should be used
            device_map: str | dict[str, Any] | None
            if device == "cpu":
                device_map = None
            elif self.sharding_manager and kwargs.get("enable_sharding", True):
                # Use sharding manager for multi-GPU
                trust_remote = kwargs.get("trust_remote_code", True)
                sharded_result = cast("Any", self.sharding_manager).load_sharded_model(
                    model_path,
                    model_class=AutoModelForCausalLM,
                    torch_dtype=torch_dtype,
                    trust_remote_code=trust_remote if isinstance(trust_remote, bool) else True,
                    **kwargs,
                )
                return cast("Any", sharded_result)
            else:
                device_map = "auto"

            # Load model
            trust_remote_param = kwargs.get("trust_remote_code", True)
            model = AutoModelForCausalLM.from_pretrained(
                str(model_path),
                device_map=device_map,
                torch_dtype=torch_dtype,
                trust_remote_code=trust_remote_param if isinstance(trust_remote_param, bool) else True,
            )

            if device == "cpu":
                model = model.to(device)  # type: ignore[arg-type]
            elif GPU_AUTOLOADER_AVAILABLE:
                # Move model to appropriate device using unified GPU system
                device_result = to_device(cast("Any", model))
                if device_result is not None:
                    model = device_result

                # Apply GPU optimizations if available
                optimized_result = optimize_for_gpu(model)
                if optimized_result is not None:
                    model = optimized_result
                    logger.info("Applied GPU optimizations to standard model")

            logger.info("Successfully loaded standard model")
            return cast("Any", model)

        except Exception as e:
            logger.exception("Failed to load standard model: %s", e)
            return None

    def load_lora_adapter(
        self,
        base_model: Any,
        adapter_path: str | Path,
        **kwargs: object,
    ) -> Any:
        """Load LoRA adapter onto a base model.

        Args:
            base_model: Base model to apply adapter to
            adapter_path: Path to LoRA adapter
            **kwargs: Additional arguments

        Returns:
            Model with LoRA adapter or None

        """
        if not HAS_PEFT or PeftModel is None or torch is None:
            logger.exception("peft and PyTorch required for LoRA adapters")
            return None

        try:
            adapter_path_obj = Path(adapter_path)

            # Get dtype and device map
            torch_dtype_param = kwargs.get("torch_dtype", torch.float16)
            device_map_param = kwargs.get("device_map", "auto")

            # Load LoRA adapter
            model = PeftModel.from_pretrained(
                base_model,
                str(adapter_path_obj),
                torch_dtype=torch_dtype_param,
                device_map=device_map_param,
            )

            if merge_adapter := kwargs.get("merge_adapter"):
                model = model.merge_and_unload()

            logger.info("Successfully loaded LoRA adapter from %s", adapter_path_obj)
            return cast("Any", model)

        except Exception as e:
            logger.exception("Failed to load LoRA adapter: %s", e)
            return None

    def apply_dynamic_quantization(
        self,
        model: Any,
        quantization_config: dict[str, object],
    ) -> Any:
        """Apply dynamic quantization to a loaded model.

        Args:
            model: Model to quantize
            quantization_config: Quantization configuration

        Returns:
            Quantized model or None

        """
        if not HAS_TORCH or torch is None:
            logger.exception("PyTorch required for dynamic quantization")
            return None

        try:
            quant_type = quantization_config.get("type", "int8")

            if quant_type == "int8":
                # Apply INT8 dynamic quantization using torch.ao.quantization
                if hasattr(torch, "ao") and hasattr(torch.ao, "quantization"):
                    quantized_model = torch.ao.quantization.quantize_dynamic(  # type: ignore[no-untyped-call]
                        model,
                        {torch.nn.Linear},
                        dtype=torch.qint8,
                    )
                    model = quantized_model
                else:
                    logger.warning("torch.ao.quantization not available, skipping quantization")
            elif quant_type == "fp16":
                # Convert to FP16
                model = cast("Any", model.half())

            logger.info("Applied %s dynamic quantization", quant_type)
            return model

        except Exception as e:
            logger.exception("Failed to apply dynamic quantization: %s", e)
            return None

    def estimate_memory_usage(
        self,
        model_path: str | Path,
        quantization_type: str = "auto",
    ) -> dict[str, float]:
        """Estimate memory usage for a model with given quantization.

        Args:
            model_path: Path to model
            quantization_type: Type of quantization

        Returns:
            Dictionary with memory estimates in GB

        """
        model_path = Path(model_path)

        # Get model size
        total_size = 0
        if model_path.is_dir():
            for file in model_path.rglob("*.bin"):
                total_size += file.stat().st_size
            for file in model_path.rglob("*.safetensors"):
                total_size += file.stat().st_size
        else:
            total_size = model_path.stat().st_size

        size_gb = total_size / (1024**3)

        # Estimate based on quantization
        estimates = {
            "disk_size_gb": size_gb,
            "fp32_memory_gb": size_gb,
            "fp16_memory_gb": size_gb / 2,
            "int8_memory_gb": size_gb / 4,
            "int4_memory_gb": size_gb / 8,
        }

        if quantization_type == "8bit":
            estimates["estimated_memory_gb"] = estimates["int8_memory_gb"] * 1.2
        elif quantization_type == "4bit":
            estimates["estimated_memory_gb"] = estimates["int4_memory_gb"] * 1.2
        elif quantization_type == "gptq":
            estimates["estimated_memory_gb"] = size_gb * 0.25
        else:
            estimates["estimated_memory_gb"] = estimates["fp16_memory_gb"] * 1.2

        return estimates

    def create_lora_config(
        self,
        r: int = 16,
        lora_alpha: int = 32,
        target_modules: list[str] | None = None,
        lora_dropout: float = 0.1,
        **kwargs: object,
    ) -> Any:
        """Create a LoRA configuration for fine-tuning.

        Args:
            r: LoRA rank
            lora_alpha: LoRA alpha parameter
            target_modules: Modules to apply LoRA to
            lora_dropout: Dropout rate
            **kwargs: Additional LoRA parameters

        Returns:
            LoRA configuration or None

        """
        if not HAS_PEFT or LoraConfig is None:
            logger.exception("peft required for LoRA configuration")
            return None

        # Default target modules for common architectures
        if target_modules is None:
            target_modules = [
                "q_proj",
                "v_proj",
                "k_proj",
                "o_proj",
                "gate_proj",
                "down_proj",
                "up_proj",
            ]

        # Extract kwargs with type checking
        bias_param = kwargs.get("bias", "none")
        bias_value: str = bias_param if isinstance(bias_param, str) else "none"

        task_type_param = kwargs.get("task_type", "CAUSAL_LM")
        task_type_value: str = task_type_param if isinstance(task_type_param, str) else "CAUSAL_LM"

        inference_mode_param = kwargs.get("inference_mode", False)
        inference_mode_value: bool = inference_mode_param if isinstance(inference_mode_param, bool) else False

        return LoraConfig(
            r=r,
            lora_alpha=lora_alpha,
            target_modules=target_modules,
            lora_dropout=lora_dropout,
            bias=bias_value,  # type: ignore[arg-type]
            task_type=task_type_value,
            inference_mode=inference_mode_value,
        )

    def get_sharding_info(self) -> dict[str, object]:
        """Get information about multi-GPU sharding capabilities.

        Returns:
            Dictionary with sharding information

        """
        if self.sharding_manager:
            result = cast("Any", self.sharding_manager).get_device_info()
            return cast("dict[str, object]", result)

        if GPU_AUTOLOADER_AVAILABLE:
            gpu_info = get_gpu_info()
            if isinstance(gpu_info, dict):
                available = gpu_info.get("available", False)
                info_obj = gpu_info.get("info", {})
                device_count = info_obj.get("device_count", 0) if isinstance(info_obj, dict) else 0

                return {
                    "cuda_available": available,
                    "device_count": device_count,
                    "sharding_available": False,
                    "reason": "Single GPU or no GPU available",
                }

        if HAS_TORCH and torch is not None:
            return {
                "cuda_available": torch.cuda.is_available(),
                "device_count": torch.cuda.device_count() if torch.cuda.is_available() else 0,
                "sharding_available": False,
                "reason": "Single GPU or no GPU available",
            }

        return {
            "cuda_available": False,
            "device_count": 0,
            "sharding_available": False,
            "reason": "No GPU support available",
        }

    def get_supported_quantization_types(self) -> list[str]:
        """Get list of supported quantization types."""
        supported_types = []

        if HAS_BITSANDBYTES:
            supported_types.extend(["8bit", "4bit"])

        if HAS_AUTO_GPTQ:
            supported_types.append("gptq")

        if HAS_TORCH:
            supported_types.extend(["dynamic", "static"])

        # Always support no quantization
        supported_types.append("none")

        return supported_types

    def quantize_model_with_bnb(self, model: Any, quantization_bits: int = 8, **kwargs: object) -> Any:
        """Quantize a model using bitsandbytes (bnb) library.

        Args:
            model: Model to quantize
            quantization_bits: Number of bits (8 or 4)
            **kwargs: Additional quantization parameters

        Returns:
            Quantized model or None

        """
        if not HAS_BITSANDBYTES or bnb is None or torch is None:
            logger.exception("bitsandbytes (bnb) and PyTorch required for this quantization method")
            return None

        try:
            # Prepare model for quantization
            for name, module in cast("Any", model.named_modules()):
                # Prepare model for quantization
                if quantization_bits == 8:
                    if isinstance(module, torch.nn.Linear):
                        # Replace with 8-bit linear layer
                        in_features = module.in_features
                        out_features = module.out_features

                        # Extract kwargs with type checking
                        has_fp16_weights_param = kwargs.get("has_fp16_weights", False)
                        has_fp16_weights = has_fp16_weights_param if isinstance(has_fp16_weights_param, bool) else False

                        threshold_param = kwargs.get("threshold", 6.0)
                        threshold = threshold_param if isinstance(threshold_param, (int, float)) else 6.0

                        # Create 8-bit linear layer using bnb.nn submodule
                        if hasattr(bnb, "nn") and hasattr(bnb.nn, "Linear8bitLt"):
                            linear_8bit = bnb.nn.Linear8bitLt(
                                in_features,
                                out_features,
                                bias=module.bias is not None,
                                has_fp16_weights=has_fp16_weights,
                                threshold=float(threshold),
                            )

                            # Copy weights using Int8Params
                            if hasattr(bnb.nn, "Int8Params"):
                                weight_params = bnb.nn.Int8Params(  # type: ignore[attr-defined]
                                    module.weight.data.clone(),
                                    requires_grad=False,
                                    has_fp16_weights=has_fp16_weights,
                                )
                                linear_8bit.weight = weight_params

                            if module.bias is not None:
                                linear_8bit.bias = torch.nn.Parameter(module.bias.clone())

                            # Replace module
                            parent: Any = model
                            child_name = name.split(".")[-1]
                            for part in name.split(".")[:-1]:
                                parent = getattr(parent, part)
                            setattr(parent, child_name, linear_8bit)

                elif quantization_bits == 4:
                    if isinstance(module, torch.nn.Linear):
                        # Use bnb's 4-bit quantization
                        in_features = module.in_features
                        out_features = module.out_features

                        # Extract kwargs with type checking
                        compress_stats_param = kwargs.get("compress_statistics", True)
                        compress_stats = compress_stats_param if isinstance(compress_stats_param, bool) else True

                        # Create 4-bit layer using LinearFP4
                        if hasattr(bnb, "nn") and hasattr(bnb.nn, "LinearFP4"):
                            linear_4bit = bnb.nn.LinearFP4(
                                in_features,
                                out_features,
                                compress_statistics=compress_stats,
                            )

                            # Copy and quantize weights using Params4bit
                            if hasattr(bnb.nn, "Params4bit"):
                                quant_type_param = kwargs.get("quant_type", "fp4")
                                quant_type_str = quant_type_param if isinstance(quant_type_param, str) else "fp4"

                                weight_params_4bit = bnb.nn.Params4bit(  # type: ignore[attr-defined]
                                    module.weight.data.clone(),
                                    requires_grad=False,
                                    compress_statistics=compress_stats,
                                    quant_type=quant_type_str,
                                )
                                linear_4bit.weight = weight_params_4bit

                            if module.bias is not None:
                                linear_4bit.bias = torch.nn.Parameter(module.bias.clone())

                            # Replace module
                            parent_4bit: Any = model
                            child_name_4bit = name.split(".")[-1]
                            for part in name.split(".")[:-1]:
                                parent_4bit = getattr(parent_4bit, part)
                            setattr(parent_4bit, child_name_4bit, linear_4bit)

            logger.info("Successfully quantized model to %d-bit using bnb", quantization_bits)
            return model

        except Exception as e:
            logger.exception("Failed to quantize model with bnb: %s", e)
            return None

    def create_gptq_config(self, bits: int = 4, group_size: int = 128, **kwargs: object) -> Any:
        """Create a GPTQ configuration using BaseQuantizeConfig.

        Args:
            bits: Number of bits for quantization
            group_size: Group size for quantization
            **kwargs: Additional configuration parameters

        Returns:
            GPTQ configuration or None

        """
        if not HAS_AUTO_GPTQ or BaseQuantizeConfig is None:
            logger.exception("auto-gptq with BaseQuantizeConfig required")
            return None

        try:
            # Extract and type-check kwargs
            damp_percent_param = kwargs.get("damp_percent", 0.1)
            damp_percent = damp_percent_param if isinstance(damp_percent_param, (int, float)) else 0.1

            desc_act_param = kwargs.get("desc_act", True)
            desc_act = desc_act_param if isinstance(desc_act_param, bool) else True

            static_groups_param = kwargs.get("static_groups", False)
            static_groups = static_groups_param if isinstance(static_groups_param, bool) else False

            sym_param = kwargs.get("sym", True)
            sym = sym_param if isinstance(sym_param, bool) else True

            true_sequential_param = kwargs.get("true_sequential", True)
            true_sequential = true_sequential_param if isinstance(true_sequential_param, bool) else True

            model_name_or_path = kwargs.get("model_name_or_path")
            model_file_base_name_param = kwargs.get("model_file_base_name", "model")
            model_file_base_name = model_file_base_name_param if isinstance(model_file_base_name_param, str) else "model"

            # Create GPTQ config using BaseQuantizeConfig
            logger.info("Created GPTQ config: %d-bit, group_size=%d", bits, group_size)
            return BaseQuantizeConfig(
                bits=bits,
                group_size=group_size,
                damp_percent=float(damp_percent),
                desc_act=desc_act,
                static_groups=static_groups,
                sym=sym,
                true_sequential=true_sequential,
                model_name_or_path=model_name_or_path,
                model_file_base_name=model_file_base_name,
            )

        except Exception as e:
            logger.exception("Failed to create GPTQ config: %s", e)
            return None

    def prepare_model_for_gptq_quantization(self, model_path: str | Path, config: Any = None, **kwargs: object) -> Any:
        """Prepare a model for GPTQ quantization using GPTQConfig.

        Args:
            model_path: Path to model
            config: BaseQuantizeConfig instance or None
            **kwargs: Additional parameters

        Returns:
            Model prepared for GPTQ quantization or None

        """
        if not HAS_TRANSFORMERS or GPTQConfig is None or AutoModelForCausalLM is None or torch is None:
            logger.exception("transformers, GPTQConfig, and PyTorch required for GPTQ quantization")
            return None

        try:
            # Create GPTQConfig if not using BaseQuantizeConfig
            gptq_config: Any
            if config is None:
                # Extract and type-check kwargs
                bits_param = kwargs.get("bits", 4)
                bits = bits_param if isinstance(bits_param, int) else 4

                group_size_param = kwargs.get("group_size", 128)
                group_size = group_size_param if isinstance(group_size_param, int) else 128

                damp_percent_param = kwargs.get("damp_percent", 0.1)
                damp_percent = damp_percent_param if isinstance(damp_percent_param, (int, float)) else 0.1

                desc_act_param = kwargs.get("desc_act", True)
                desc_act = desc_act_param if isinstance(desc_act_param, bool) else True

                static_groups_param = kwargs.get("static_groups", False)
                static_groups = static_groups_param if isinstance(static_groups_param, bool) else False

                sym_param = kwargs.get("sym", True)
                sym = sym_param if isinstance(sym_param, bool) else True

                true_sequential_param = kwargs.get("true_sequential", True)
                true_sequential = true_sequential_param if isinstance(true_sequential_param, bool) else True

                gptq_config = GPTQConfig(
                    bits=bits,
                    group_size=group_size,
                    damp_percent=float(damp_percent),
                    desc_act=desc_act,
                    static_groups=static_groups,
                    sym=sym,
                    true_sequential=true_sequential,
                )
            else:
                # Convert BaseQuantizeConfig to GPTQConfig parameters
                config_any = cast("Any", config)
                gptq_config = GPTQConfig(
                    bits=config_any.bits,
                    group_size=config_any.group_size,
                    damp_percent=config_any.damp_percent,
                    desc_act=config_any.desc_act,
                    static_groups=config_any.static_groups,
                    sym=config_any.sym,
                    true_sequential=config_any.true_sequential,
                )

            # Load model with GPTQ config
            trust_remote_param = kwargs.get("trust_remote_code", True)
            trust_remote = trust_remote_param if isinstance(trust_remote_param, bool) else True

            logger.info("Successfully prepared model for GPTQ quantization")
            return AutoModelForCausalLM.from_pretrained(
                str(model_path),
                quantization_config=gptq_config,
                device_map="auto",
                trust_remote_code=trust_remote,
                torch_dtype=torch.float16,
            )

        except Exception as e:
            logger.exception("Failed to prepare model for GPTQ: %s", e)
            return None

    def create_quantization_config(self, quantization_type: str) -> dict[str, object]:
        """Create quantization configuration for the specified type."""
        if quantization_type == "8bit":
            if HAS_BITSANDBYTES and HAS_TRANSFORMERS:
                return {
                    "load_in_8bit": True,
                    "llm_int8_threshold": 6.0,
                    "llm_int8_has_fp16_weight": False,
                    "llm_int8_enable_fp32_cpu_offload": True,
                }
            logger.warning("8-bit quantization requires bitsandbytes and transformers")
            return {"quantization_type": "8bit", "available": False}

        if quantization_type == "4bit":
            if HAS_BITSANDBYTES and HAS_TRANSFORMERS:
                return {
                    "load_in_4bit": True,
                    "bnb_4bit_compute_dtype": "float16",
                    "bnb_4bit_use_double_quant": True,
                    "bnb_4bit_quant_type": "nf4",
                }
            logger.warning("4-bit quantization requires bitsandbytes and transformers")
            return {"quantization_type": "4bit", "available": False}

        if quantization_type == "gptq":
            if HAS_AUTO_GPTQ:
                return {
                    "bits": 4,
                    "group_size": 128,
                    "desc_act": False,
                    "disable_exllama": False,
                }
            logger.warning("GPTQ quantization requires auto-gptq")
            return {"quantization_type": "gptq", "available": False}

        if quantization_type == "dynamic":
            if HAS_TORCH and torch is not None:
                # Use torch.ao.quantization if available
                if hasattr(torch, "ao") and hasattr(torch.ao, "quantization"):
                    default_qconfig = getattr(torch.ao.quantization, "default_dynamic_qconfig", None)
                    if default_qconfig is not None:
                        return {
                            "qconfig_spec": {
                                "": default_qconfig,
                            },
                            "dtype": "qint8",
                            "qconfig_dict": None,
                        }
                logger.warning("torch.ao.quantization.default_dynamic_qconfig not available")
                return {"quantization_type": "dynamic", "available": False}
            logger.warning("Dynamic quantization requires PyTorch")
            return {"quantization_type": "dynamic", "available": False}

        if quantization_type == "static":
            if HAS_TORCH and torch is not None:
                # Use torch.ao.quantization if available
                if hasattr(torch, "ao") and hasattr(torch.ao, "quantization"):
                    default_static_qconfig = getattr(torch.ao.quantization, "default_qconfig", None)
                    if default_static_qconfig is not None:
                        return {
                            "qconfig_spec": {
                                "": default_static_qconfig,
                            },
                            "calibration_data_required": True,
                            "dtype": "qint8",
                        }
                logger.warning("torch.ao.quantization.default_qconfig not available")
                return {"quantization_type": "static", "available": False}
            logger.warning("Static quantization requires PyTorch")
            return {"quantization_type": "static", "available": False}

        if quantization_type == "none":
            return {
                "quantization_type": "none",
                "description": "No quantization applied",
            }

        raise ValueError(f"Unsupported quantization type: {quantization_type}")

    def cleanup_memory(self) -> None:
        """Clean up GPU memory after model operations."""
        if GPU_AUTOLOADER_AVAILABLE:
            gpu_autoloader.synchronize()
            # Let the unified system handle memory cleanup
            gpu_info = get_gpu_info()
            if isinstance(gpu_info, dict):
                gpu_type = gpu_info.get("type")
                if gpu_type == "nvidia_cuda" and torch is not None and torch.cuda.is_available():
                    torch.cuda.empty_cache()
                elif gpu_type == "intel_xpu" and torch is not None and hasattr(torch, "xpu"):
                    torch_xpu = torch.xpu
                    if hasattr(torch_xpu, "empty_cache"):
                        torch_xpu.empty_cache()
        elif torch is not None and torch.cuda.is_available():
            torch.cuda.empty_cache()

        if self.sharding_manager:
            cast("Any", self.sharding_manager).cleanup_memory()
        gc.collect()
        logger.info("Cleaned up memory")


# Global instance
_QUANTIZATION_MANAGER: QuantizationManager | None = None


def get_quantization_manager() -> QuantizationManager:
    """Get the global quantization manager."""
    global _QUANTIZATION_MANAGER
    if _QUANTIZATION_MANAGER is None:
        _QUANTIZATION_MANAGER = QuantizationManager()
    return _QUANTIZATION_MANAGER
