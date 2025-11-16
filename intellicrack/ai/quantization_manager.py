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
from typing import Any, TypeVar

from ..utils.logger import get_logger
from .model_sharding import get_sharding_manager

ModelType = TypeVar("ModelType")
ConfigType = TypeVar("ConfigType")

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


logger = get_logger(__name__)

# Try to import quantization libraries
try:
    import bitsandbytes as bnb

    HAS_BITSANDBYTES = True
except (ImportError, AttributeError) as e:
    # AttributeError can occur if bitsandbytes has internal import issues
    logger.debug("Optional dependency bitsandbytes not available: %s", e)
    bnb = None
    HAS_BITSANDBYTES = False
except Exception as e:
    # Catch any other errors from bitsandbytes initialization
    logger.debug("Error initializing bitsandbytes: %s", e)
    bnb = None
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
AutoAWQForCausalLM = None

try:
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        GPTQConfig,
    )

    HAS_TRANSFORMERS = True
except ImportError as e:
    logger.error("Import error in quantization_manager: %s", e)
    AutoModelForCausalLM = None
    AutoTokenizer = None
    BitsAndBytesConfig = None
    GPTQConfig = None
    HAS_TRANSFORMERS = False

try:
    from peft import LoraConfig, PeftModel, get_peft_model, prepare_model_for_kbit_training

    HAS_PEFT = True
except ImportError as e:
    logger.error("Import error in quantization_manager: %s", e)
    PeftModel = None
    LoraConfig = None
    get_peft_model = None
    prepare_model_for_kbit_training = None
    HAS_PEFT = False


class QuantizationManager:
    """Manages model quantization for efficient inference."""

    def __init__(self) -> None:
        """Initialize the quantization manager."""
        self.loaded_models: dict[str, ModelType] = {}
        self.quantization_configs: dict[str, dict[str, Any]] = {}
        self.sharding_manager: Any = None

        # Check available backends
        self.available_backends: dict[str, bool] = {
            "bitsandbytes": HAS_BITSANDBYTES,
            "auto_gptq": HAS_AUTO_GPTQ,
            "transformers": HAS_TRANSFORMERS,
            "peft": HAS_PEFT,
        }

        logger.info(f"Quantization backends available: {self.available_backends}")

        # Initialize sharding manager if multi-GPU available
        if GPU_AUTOLOADER_AVAILABLE:
            gpu_info = get_gpu_info()
            if gpu_info["available"] and gpu_info["info"].get("device_count", 1) > 1:
                self.sharding_manager = get_sharding_manager()
                logger.info(f"Multi-GPU sharding enabled with {gpu_info['info']['device_count']} devices")
        elif HAS_TORCH and torch.cuda.device_count() > 1:
            self.sharding_manager = get_sharding_manager()
            logger.info(f"Multi-GPU sharding enabled with {torch.cuda.device_count()} devices")

    def load_quantized_model(
        self,
        model_path: str | Path,
        quantization_type: str = "auto",
        device: str = "auto",
        **kwargs: Any,
    ) -> ModelType | None:
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

        logger.info(f"Loading model with {quantization_type} quantization on {device}")

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
            logger.error(f"Failed to load quantized model: {e}")
            return None

    def _get_best_device(self) -> str:
        """Get the best available device for model loading."""
        if GPU_AUTOLOADER_AVAILABLE:
            return get_device()
        if HAS_TORCH and torch.cuda.is_available():
            return "cuda"
        if HAS_TORCH and hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
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

    def _load_8bit_model(self, model_path: Path, device: str, **kwargs: Any) -> ModelType | None:
        """Load model with 8-bit quantization using bitsandbytes."""
        if not HAS_BITSANDBYTES or not HAS_TRANSFORMERS:
            logger.error("bitsandbytes and transformers required for 8-bit quantization")
            return None

        if device == "cpu":
            logger.error("8-bit quantization requires CUDA device")
            return None

        try:
            # Configure 8-bit quantization
            quantization_config = BitsAndBytesConfig(
                load_in_8bit=True,
                bnb_8bit_compute_dtype=torch.float16,
                bnb_8bit_use_double_quant=True,
                bnb_8bit_quant_type="nf4",
            )

            # Check if multi-GPU sharding should be used
            device_map = "auto"
            if self.sharding_manager and kwargs.get("enable_sharding", True):
                device_map = self.sharding_manager.create_device_map(
                    model_path,
                    max_memory=kwargs.get("max_memory"),
                    no_split_module_classes=kwargs.get("no_split_module_classes"),
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
            return model

        except Exception as e:
            logger.error(f"Failed to load 8-bit model: {e}")
            return None

    def _load_4bit_model(self, model_path: Path, device: str, **kwargs: Any) -> ModelType | None:
        """Load model with 4-bit quantization using bitsandbytes."""
        if not HAS_BITSANDBYTES or not HAS_TRANSFORMERS:
            logger.error("bitsandbytes and transformers required for 4-bit quantization")
            return None

        if device == "cpu":
            logger.error("4-bit quantization requires CUDA device")
            return None

        try:
            # Configure 4-bit quantization
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
                bnb_4bit_quant_type="nf4",
            )

            # Check if multi-GPU sharding should be used
            device_map = "auto"
            if self.sharding_manager and kwargs.get("enable_sharding", True):
                device_map = self.sharding_manager.create_device_map(
                    model_path,
                    max_memory=kwargs.get("max_memory"),
                    no_split_module_classes=kwargs.get("no_split_module_classes"),
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
            if kwargs.get("prepare_for_training", False) and HAS_PEFT:
                model = prepare_model_for_kbit_training(model)

            logger.info("Successfully loaded 4-bit quantized model")
            return model

        except Exception as e:
            logger.error(f"Failed to load 4-bit model: {e}")
            return None

    def _load_gptq_model(self, model_path: Path, device: str, **kwargs: Any) -> ModelType | None:
        """Load GPTQ quantized model."""
        if not HAS_AUTO_GPTQ:
            logger.error("auto-gptq required for GPTQ models")
            return None

        if device == "cpu":
            logger.error("GPTQ models require CUDA device")
            return None

        try:
            # Load model
            model = AutoGPTQForCausalLM.from_quantized(
                str(model_path),
                device_map="auto",
                trust_remote_code=kwargs.get("trust_remote_code", True),
                use_safetensors=True,
                inject_fused_attention=kwargs.get("fused_attention", True),
                inject_fused_mlp=kwargs.get("fused_mlp", True),
            )

            logger.info("Successfully loaded GPTQ model")
            return model

        except Exception as e:
            logger.error(f"Failed to load GPTQ model: {e}")
            return None

    def _load_standard_model(self, model_path: Path, device: str, **kwargs: Any) -> ModelType | None:
        """Load model without quantization."""
        if not HAS_TRANSFORMERS:
            logger.error("transformers required for model loading")
            return None

        try:
            # Determine torch dtype
            torch_dtype = kwargs.get("torch_dtype", "auto")
            if torch_dtype == "auto":
                torch_dtype = torch.float16 if device != "cpu" else torch.float32

            # Check if multi-GPU sharding should be used
            if device == "cpu":
                device_map = None
            elif self.sharding_manager and kwargs.get("enable_sharding", True):
                # Use sharding manager for multi-GPU
                return self.sharding_manager.load_sharded_model(
                    model_path,
                    model_class=AutoModelForCausalLM,
                    torch_dtype=torch_dtype,
                    trust_remote_code=kwargs.get("trust_remote_code", True),
                    **kwargs,
                )
            else:
                device_map = "auto"

            # Load model
            model = AutoModelForCausalLM.from_pretrained(
                str(model_path),
                device_map=device_map,
                torch_dtype=torch_dtype,
                trust_remote_code=kwargs.get("trust_remote_code", True),
            )

            if device == "cpu":
                model = model.to(device)
            elif GPU_AUTOLOADER_AVAILABLE:
                # Move model to appropriate device using unified GPU system
                model = to_device(model, device)

                # Apply GPU optimizations if available
                if optimize_for_gpu:
                    optimized = optimize_for_gpu(model)
                    if optimized is not None:
                        model = optimized
                        logger.info("Applied GPU optimizations to standard model")

            logger.info("Successfully loaded standard model")
            return model

        except Exception as e:
            logger.error(f"Failed to load standard model: {e}")
            return None

    def load_lora_adapter(
        self,
        base_model: ModelType,
        adapter_path: str | Path,
        **kwargs: Any,
    ) -> ModelType | None:
        """Load LoRA adapter onto a base model.

        Args:
            base_model: Base model to apply adapter to
            adapter_path: Path to LoRA adapter
            **kwargs: Additional arguments

        Returns:
            Model with LoRA adapter or None

        """
        if not HAS_PEFT:
            logger.error("peft required for LoRA adapters")
            return None

        try:
            adapter_path = Path(adapter_path)

            # Load LoRA adapter
            model = PeftModel.from_pretrained(
                base_model,
                str(adapter_path),
                torch_dtype=kwargs.get("torch_dtype", torch.float16),
                device_map=kwargs.get("device_map", "auto"),
            )

            # Merge adapter if requested
            if kwargs.get("merge_adapter", False):
                model = model.merge_and_unload()

            logger.info(f"Successfully loaded LoRA adapter from {adapter_path}")
            return model

        except Exception as e:
            logger.error(f"Failed to load LoRA adapter: {e}")
            return None

    def apply_dynamic_quantization(
        self,
        model: ModelType,
        quantization_config: dict[str, Any],
    ) -> ModelType | None:
        """Apply dynamic quantization to a loaded model.

        Args:
            model: Model to quantize
            quantization_config: Quantization configuration

        Returns:
            Quantized model or None

        """
        try:
            quant_type = quantization_config.get("type", "int8")

            if quant_type == "int8":
                # Apply INT8 dynamic quantization
                model = torch.quantization.quantize_dynamic(
                    model,
                    {torch.nn.Linear},
                    dtype=torch.qint8,
                )
            elif quant_type == "fp16":
                # Convert to FP16
                model = model.half()

            logger.info(f"Applied {quant_type} dynamic quantization")
            return model

        except Exception as e:
            logger.error(f"Failed to apply dynamic quantization: {e}")
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
        **kwargs: Any,
    ) -> ConfigType | None:
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
        if not HAS_PEFT:
            logger.error("peft required for LoRA configuration")
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

        config = LoraConfig(
            r=r,
            lora_alpha=lora_alpha,
            target_modules=target_modules,
            lora_dropout=lora_dropout,
            bias=kwargs.get("bias", "none"),
            task_type=kwargs.get("task_type", "CAUSAL_LM"),
            inference_mode=kwargs.get("inference_mode", False),
        )

        return config

    def get_sharding_info(self) -> dict[str, Any]:
        """Get information about multi-GPU sharding capabilities.

        Returns:
            Dictionary with sharding information

        """
        if self.sharding_manager:
            return self.sharding_manager.get_device_info()
        gpu_info = get_gpu_info() if GPU_AUTOLOADER_AVAILABLE else {}
        return {
            "cuda_available": gpu_info.get("available", False) if GPU_AUTOLOADER_AVAILABLE else torch.cuda.is_available(),
            "device_count": gpu_info.get("info", {}).get("device_count", 0)
            if GPU_AUTOLOADER_AVAILABLE
            else (torch.cuda.device_count() if torch.cuda.is_available() else 0),
            "sharding_available": False,
            "reason": "Single GPU or no GPU available",
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

    def quantize_model_with_bnb(self, model: ModelType, quantization_bits: int = 8, **kwargs: Any) -> ModelType | None:
        """Quantize a model using bitsandbytes (bnb) library.

        Args:
            model: Model to quantize
            quantization_bits: Number of bits (8 or 4)
            **kwargs: Additional quantization parameters

        Returns:
            Quantized model or None

        """
        if not HAS_BITSANDBYTES or not bnb:
            logger.error("bitsandbytes (bnb) required for this quantization method")
            return None

        try:
            # Prepare model for quantization
            if quantization_bits == 8:
                # Convert model layers to 8-bit using bnb
                for name, module in model.named_modules():
                    if isinstance(module, torch.nn.Linear):
                        # Replace with 8-bit linear layer
                        in_features = module.in_features
                        out_features = module.out_features

                        # Create 8-bit linear layer
                        linear_8bit = bnb.nn.Linear8bitLt(
                            in_features,
                            out_features,
                            bias=module.bias is not None,
                            has_fp16_weights=kwargs.get("has_fp16_weights", False),
                            threshold=kwargs.get("threshold", 6.0),
                        )

                        # Copy weights
                        linear_8bit.weight = bnb.nn.Int8Params(
                            module.weight.data.clone(),
                            requires_grad=False,
                            has_fp16_weights=kwargs.get("has_fp16_weights", False),
                        )

                        if module.bias is not None:
                            linear_8bit.bias = module.bias.clone()

                        # Replace module
                        parent = model
                        child_name = name.split(".")[-1]
                        for part in name.split(".")[:-1]:
                            parent = getattr(parent, part)
                        setattr(parent, child_name, linear_8bit)

            elif quantization_bits == 4:
                # 4-bit quantization using bnb
                for name, module in model.named_modules():
                    if isinstance(module, torch.nn.Linear):
                        # Use bnb's 4-bit quantization
                        in_features = module.in_features
                        out_features = module.out_features

                        # Create 4-bit params
                        linear_4bit = bnb.nn.LinearFP4(
                            in_features,
                            out_features,
                            compress_statistics=kwargs.get("compress_statistics", True),
                            quant_type=kwargs.get("quant_type", "fp4"),
                        )

                        # Copy and quantize weights
                        linear_4bit.weight = bnb.nn.Params4bit(
                            module.weight.data.clone(),
                            requires_grad=False,
                            compress_statistics=kwargs.get("compress_statistics", True),
                            quant_type=kwargs.get("quant_type", "fp4"),
                        )

                        if module.bias is not None:
                            linear_4bit.bias = module.bias.clone()

                        # Replace module
                        parent = model
                        child_name = name.split(".")[-1]
                        for part in name.split(".")[:-1]:
                            parent = getattr(parent, part)
                        setattr(parent, child_name, linear_4bit)

            logger.info(f"Successfully quantized model to {quantization_bits}-bit using bnb")
            return model

        except Exception as e:
            logger.error(f"Failed to quantize model with bnb: {e}")
            return None

    def create_gptq_config(self, bits: int = 4, group_size: int = 128, **kwargs: Any) -> ConfigType | None:
        """Create a GPTQ configuration using BaseQuantizeConfig.

        Args:
            bits: Number of bits for quantization
            group_size: Group size for quantization
            **kwargs: Additional configuration parameters

        Returns:
            GPTQ configuration or None

        """
        if not HAS_AUTO_GPTQ or not BaseQuantizeConfig:
            logger.error("auto-gptq with BaseQuantizeConfig required")
            return None

        try:
            # Create GPTQ config using BaseQuantizeConfig
            config = BaseQuantizeConfig(
                bits=bits,
                group_size=group_size,
                damp_percent=kwargs.get("damp_percent", 0.1),
                desc_act=kwargs.get("desc_act", True),
                static_groups=kwargs.get("static_groups", False),
                sym=kwargs.get("sym", True),
                true_sequential=kwargs.get("true_sequential", True),
                model_name_or_path=kwargs.get("model_name_or_path"),
                model_file_base_name=kwargs.get("model_file_base_name", "model"),
            )

            logger.info(f"Created GPTQ config: {bits}-bit, group_size={group_size}")
            return config

        except Exception as e:
            logger.error(f"Failed to create GPTQ config: {e}")
            return None

    def prepare_model_for_gptq_quantization(self, model_path: str | Path, config: ConfigType | None = None, **kwargs: Any) -> ModelType | None:
        """Prepare a model for GPTQ quantization using GPTQConfig.

        Args:
            model_path: Path to model
            config: BaseQuantizeConfig instance or None
            **kwargs: Additional parameters

        Returns:
            Model prepared for GPTQ quantization or None

        """
        if not HAS_TRANSFORMERS or not GPTQConfig:
            logger.error("transformers with GPTQConfig required")
            return None

        try:
            # Create GPTQConfig if not using BaseQuantizeConfig
            if config is None and GPTQConfig:
                gptq_config = GPTQConfig(
                    bits=kwargs.get("bits", 4),
                    group_size=kwargs.get("group_size", 128),
                    damp_percent=kwargs.get("damp_percent", 0.1),
                    desc_act=kwargs.get("desc_act", True),
                    static_groups=kwargs.get("static_groups", False),
                    sym=kwargs.get("sym", True),
                    true_sequential=kwargs.get("true_sequential", True),
                )
            else:
                # Convert BaseQuantizeConfig to GPTQConfig parameters
                gptq_config = GPTQConfig(
                    bits=config.bits,
                    group_size=config.group_size,
                    damp_percent=config.damp_percent,
                    desc_act=config.desc_act,
                    static_groups=config.static_groups,
                    sym=config.sym,
                    true_sequential=config.true_sequential,
                )

            # Load model with GPTQ config
            model = AutoModelForCausalLM.from_pretrained(
                str(model_path),
                quantization_config=gptq_config,
                device_map="auto",
                trust_remote_code=kwargs.get("trust_remote_code", True),
                torch_dtype=torch.float16,
            )

            logger.info("Successfully prepared model for GPTQ quantization")
            return model

        except Exception as e:
            logger.error(f"Failed to prepare model for GPTQ: {e}")
            return None

    def create_quantization_config(self, quantization_type: str) -> dict:
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
            if HAS_TORCH:
                return {
                    "qconfig_spec": {
                        "": torch.quantization.default_dynamic_qconfig,
                    },
                    "dtype": "qint8",
                    "qconfig_dict": None,
                }
            logger.warning("Dynamic quantization requires PyTorch")
            return {"quantization_type": "dynamic", "available": False}

        if quantization_type == "static":
            if HAS_TORCH:
                return {
                    "qconfig_spec": {
                        "": torch.quantization.default_qconfig,
                    },
                    "calibration_data_required": True,
                    "dtype": "qint8",
                }
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
            if gpu_info["type"] == "nvidia_cuda" and torch.cuda.is_available():
                torch.cuda.empty_cache()
            elif gpu_info["type"] == "intel_xpu" and hasattr(torch, "xpu"):
                if hasattr(torch.xpu, "empty_cache"):
                    torch.xpu.empty_cache()
        elif torch.cuda.is_available():
            torch.cuda.empty_cache()

        if self.sharding_manager:
            self.sharding_manager.cleanup_memory()
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
