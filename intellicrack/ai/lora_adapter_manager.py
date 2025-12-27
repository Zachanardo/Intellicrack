"""LoRA/QLoRA Adapter Manager for Intellicrack.

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

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from ..utils.logger import get_logger


if TYPE_CHECKING:
    from peft import (
        PeftConfig as PeftConfigType,
        PeftModel as PeftModelType,
    )

ModelType = TypeVar("ModelType")
ConfigType = TypeVar("ConfigType")

logger = get_logger(__name__)

# Optional torch import
HAS_TORCH = False
torch: Any = None
TorchModule: Any = None
try:
    import torch

    HAS_TORCH = True
    TorchModule = Any
except ImportError as e:
    logger.exception("Import error in lora_adapter_manager: %s", e)

# Try to import PEFT
AdaLoraConfig: Any = None
LoraConfig: Any = None
PeftConfig: Any = None
PeftModel: Any = None
TaskType: Any = None
get_peft_model: Any = None
prepare_model_for_kbit_training: Any = None
GetPeftModelFunc: Any = None
PrepareModelFunc: Any = None
HAS_PEFT = False

try:
    from peft import AdaLoraConfig, LoraConfig, PeftConfig, PeftModel, TaskType, get_peft_model, prepare_model_for_kbit_training

    HAS_PEFT = True
    GetPeftModelFunc = Callable[..., Any]
    PrepareModelFunc = Callable[..., Any]
except ImportError as e:
    logger.exception("Import error in lora_adapter_manager: %s", e)

AutoModelForCausalLM: Any = None
AutoTokenizer: Any = None
HAS_TRANSFORMERS = False

try:
    from transformers import AutoModelForCausalLM, AutoTokenizer

    HAS_TRANSFORMERS = True
except ImportError as e:
    logger.exception("Import error in lora_adapter_manager: %s", e)


@dataclass
class AdapterConfig:
    """Configuration for a LoRA/QLoRA adapter."""

    adapter_type: str
    r: int = 16
    lora_alpha: int = 32
    target_modules: list[str] | None = None
    lora_dropout: float = 0.1
    bias: str = "none"
    task_type: str = "CAUSAL_LM"
    inference_mode: bool = True
    fan_in_fan_out: bool = False
    modules_to_save: list[str] | None = None
    target_r: int = 8
    init_r: int = 12


class LoRAAdapterManager:
    """Manages LoRA and QLoRA adapters for efficient fine-tuning."""

    def __init__(self, cache_dir: str | Path | None = None) -> None:
        """Initialize the LoRA adapter manager.

        Args:
            cache_dir: Directory to cache downloaded adapters

        """
        resolved_cache_dir: Path
        if cache_dir is None:
            resolved_cache_dir = Path.home() / ".intellicrack" / "lora_adapters"
        else:
            resolved_cache_dir = Path(cache_dir) if isinstance(cache_dir, str) else cache_dir

        self.cache_dir: Path = resolved_cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.loaded_adapters: dict[str, Any] = {}
        self.adapter_configs: dict[str, Any] = {}

        if not HAS_PEFT:
            logger.warning("PEFT not available - LoRA functionality limited")
        else:
            logger.info("LoRA adapter manager initialized")

    def create_lora_config(
        self,
        adapter_type: str = "lora",
        r: int = 16,
        lora_alpha: int = 32,
        target_modules: list[str] | None = None,
        lora_dropout: float = 0.1,
        **kwargs: object,
    ) -> Any:
        """Create a LoRA configuration.

        Args:
            adapter_type: Type of adapter ("lora", "qlora", "adalora")
            r: LoRA rank
            lora_alpha: LoRA alpha parameter
            target_modules: Modules to apply LoRA to
            lora_dropout: Dropout rate
            **kwargs: Additional parameters

        Returns:
            PEFT configuration or None

        """
        if not HAS_PEFT:
            logger.exception("PEFT required for LoRA configuration")
            return None

        # Default target modules for common architectures
        if target_modules is None:
            model_type_val = kwargs.get("model_type")
            model_type_str: str | None = str(model_type_val) if model_type_val is not None else None
            target_modules = self._get_default_target_modules(model_type_str)

        try:
            bias_val = kwargs.get("bias", "none")
            bias_str: str = str(bias_val) if bias_val is not None else "none"

            task_type_val = kwargs.get("task_type", TaskType.CAUSAL_LM if TaskType is not None else "CAUSAL_LM")

            inference_mode_val = kwargs.get("inference_mode", False)
            inference_mode_bool: bool = bool(inference_mode_val) if inference_mode_val is not None else False

            target_r_val = kwargs.get("target_r", 8)
            target_r_int: int = int(target_r_val) if isinstance(target_r_val, (int, float)) else 8

            init_r_val = kwargs.get("init_r", 12)
            init_r_int: int = int(init_r_val) if isinstance(init_r_val, (int, float)) else 12

            fan_in_fan_out_val = kwargs.get("fan_in_fan_out", False)
            fan_in_fan_out_bool: bool = bool(fan_in_fan_out_val) if fan_in_fan_out_val is not None else False

            modules_to_save_val = kwargs.get("modules_to_save")
            modules_to_save_list: list[str] | None = list(modules_to_save_val) if isinstance(modules_to_save_val, list) else None

            result: Any
            return (
                AdaLoraConfig(
                    r=r,
                    lora_alpha=lora_alpha,
                    target_modules=target_modules,
                    lora_dropout=lora_dropout,
                    bias=bias_str,
                    task_type=task_type_val,
                    inference_mode=inference_mode_bool,
                    target_r=target_r_int,
                    init_r=init_r_int,
                )
                if adapter_type == "adalora"
                else LoraConfig(
                    r=r,
                    lora_alpha=lora_alpha,
                    target_modules=target_modules,
                    lora_dropout=lora_dropout,
                    bias=bias_str,
                    task_type=task_type_val,
                    inference_mode=inference_mode_bool,
                    fan_in_fan_out=fan_in_fan_out_bool,
                    modules_to_save=modules_to_save_list,
                )
            )
        except Exception as e:
            logger.exception("Failed to create LoRA config: %s", e)
            return None

    def _get_default_target_modules(self, model_type: str | None = None) -> list[str]:
        """Get default target modules for common model architectures.

        Args:
            model_type: Type of model architecture

        Returns:
            List of target module names

        """
        # Common patterns for different architectures
        default_patterns = {
            "llama": ["q_proj", "v_proj", "k_proj", "o_proj", "gate_proj", "down_proj", "up_proj"],
            "mistral": [
                "q_proj",
                "v_proj",
                "k_proj",
                "o_proj",
                "gate_proj",
                "down_proj",
                "up_proj",
            ],
            "gpt2": ["c_attn", "c_proj", "c_fc"],
            "gpt_neox": ["query_key_value", "dense", "dense_h_to_4h", "dense_4h_to_h"],
            "bloom": ["query_key_value", "dense", "dense_h_to_4h", "dense_4h_to_h"],
            "opt": ["q_proj", "v_proj", "k_proj", "out_proj", "fc1", "fc2"],
            "bert": ["query", "key", "value", "dense"],
            "roberta": ["query", "key", "value", "dense"],
            "t5": ["q", "v", "k", "o", "wi_0", "wi_1", "wo"],
        }

        if model_type and model_type.lower() in default_patterns:
            return default_patterns[model_type.lower()]

        # Default to common attention projection layers
        return ["q_proj", "v_proj", "k_proj", "o_proj"]

    def apply_lora_to_model(
        self,
        model: Any,
        lora_config: Any,
        adapter_name: str = "default",
    ) -> Any:
        """Apply LoRA adapter to a model.

        Args:
            model: Base model
            lora_config: LoRA configuration
            adapter_name: Name for the adapter

        Returns:
            Model with LoRA adapter or None

        """
        if not HAS_PEFT or get_peft_model is None:
            logger.exception("PEFT required to apply LoRA")
            return None

        try:
            peft_model: Any = get_peft_model(model, lora_config, adapter_name=adapter_name)

            trainable_params: int = sum(p.numel() for p in peft_model.parameters() if p.requires_grad)
            total_params: int = sum(p.numel() for p in peft_model.parameters())

            logger.info(
                "Applied LoRA adapter '%s': %s trainable params / %s total params (%.2f%% trainable)",
                adapter_name,
                f"{trainable_params:,}",
                f"{total_params:,}",
                100 * trainable_params / total_params,
            )

            return peft_model

        except Exception as e:
            logger.exception("Failed to apply LoRA: %s", e)
            return None

    def load_adapter(
        self,
        base_model: Any,
        adapter_path: str | Path,
        adapter_name: str = "default",
        **kwargs: object,
    ) -> Any:
        """Load a LoRA adapter from disk.

        Args:
            base_model: Base model to apply adapter to
            adapter_path: Path to adapter files
            adapter_name: Name for the adapter
            **kwargs: Additional arguments

        Returns:
            Model with loaded adapter or None

        """
        if not HAS_PEFT or PeftModel is None:
            logger.exception("PEFT required to load adapters")
            return None

        try:
            resolved_adapter_path: Path = Path(adapter_path)

            cache_key: str = f"{resolved_adapter_path}_{adapter_name}"
            if cache_key in self.loaded_adapters:
                logger.info("Using cached adapter: %s", adapter_name)
                return self.loaded_adapters[cache_key]

            torch_dtype_val = kwargs.get("torch_dtype", torch.float16 if torch is not None else None)
            device_map_val = kwargs.get("device_map", "auto")
            is_trainable_val = kwargs.get("is_trainable", False)
            is_trainable_bool: bool = bool(is_trainable_val) if is_trainable_val is not None else False

            model: Any = PeftModel.from_pretrained(
                base_model,
                str(resolved_adapter_path),
                adapter_name=adapter_name,
                torch_dtype=torch_dtype_val,
                device_map=device_map_val,
                is_trainable=is_trainable_bool,
            )

            if kwargs.get("merge_adapter"):
                model = model.merge_and_unload()
                logger.info("Merged adapter '%s' into base model", adapter_name)

            self.loaded_adapters[cache_key] = model

            logger.info("Loaded LoRA adapter from %s", resolved_adapter_path)
            return model

        except Exception as e:
            logger.exception("Failed to load adapter: %s", e)
            return None

    def save_adapter(
        self,
        model: Any,
        save_path: str | Path,
        adapter_name: str = "default",
        save_config: bool = True,
    ) -> bool:
        """Save a LoRA adapter to disk.

        Args:
            model: Model with LoRA adapter
            save_path: Path to save adapter
            adapter_name: Name of adapter to save
            save_config: Whether to save adapter config

        Returns:
            True if successful, False otherwise

        """
        if not HAS_PEFT:
            logger.exception("PEFT required to save adapters")
            return False

        try:
            save_path = Path(save_path)
            save_path.mkdir(parents=True, exist_ok=True)

            # Save adapter
            if hasattr(model, "save_pretrained"):
                model.save_pretrained(
                    str(save_path),
                    adapter_name=adapter_name,
                    save_config=save_config,
                )
                logger.info("Saved LoRA adapter to %s", save_path)
                return True
            logger.exception("Model does not support save_pretrained")
            return False

        except Exception as e:
            logger.exception("Failed to save adapter: %s", e)
            return False

    def prepare_model_for_qlora(
        self,
        model: Any,
        use_gradient_checkpointing: bool = True,
        gradient_checkpointing_kwargs: dict[str, Any] | None = None,
    ) -> Any:
        """Prepare a model for QLoRA training.

        Args:
            model: Quantized model
            use_gradient_checkpointing: Whether to use gradient checkpointing
            gradient_checkpointing_kwargs: Arguments for gradient checkpointing

        Returns:
            Prepared model

        """
        if not HAS_PEFT or prepare_model_for_kbit_training is None:
            logger.exception("PEFT required for QLoRA preparation")
            return model

        try:
            prepared_model: Any = prepare_model_for_kbit_training(
                model,
                use_gradient_checkpointing=use_gradient_checkpointing,
                gradient_checkpointing_kwargs=gradient_checkpointing_kwargs,
            )

            logger.info("Prepared model for QLoRA training")
            return prepared_model

        except Exception as e:
            logger.exception("Failed to prepare model for QLoRA: %s", e)
            return model

    def list_adapters(self, model: Any) -> list[str]:
        """List all adapters loaded in a model.

        Args:
            model: PEFT model

        Returns:
            List of adapter names

        """
        return list(model.peft_config.keys()) if hasattr(model, "peft_config") else []

    def set_adapter(self, model: Any, adapter_name: str) -> bool:
        """Set the active adapter in a multi-adapter model.

        Args:
            model: PEFT model with multiple adapters
            adapter_name: Name of adapter to activate

        Returns:
            True if successful, False otherwise

        """
        try:
            if hasattr(model, "set_adapter"):
                model.set_adapter(adapter_name)
                logger.info("Activated adapter: %s", adapter_name)
                return True
            logger.exception("Model does not support multiple adapters")
            return False

        except Exception as e:
            logger.exception("Failed to set adapter: %s", e)
            return False

    def merge_adapters(
        self,
        model: Any,
        adapter_names: list[str],
        weights: list[float] | None = None,
        new_adapter_name: str = "merged",
    ) -> bool:
        """Merge multiple adapters with weighted combination.

        Args:
            model: PEFT model with multiple adapters
            adapter_names: Names of adapters to merge
            weights: Weights for each adapter (equal if None)
            new_adapter_name: Name for merged adapter

        Returns:
            True if successful, False otherwise

        """
        try:
            if not hasattr(model, "add_weighted_adapter"):
                logger.exception("Model does not support adapter merging")
                return False

            if weights is None:
                weights = [1.0 / len(adapter_names)] * len(adapter_names)

            model.add_weighted_adapter(
                adapter_names,
                weights,
                new_adapter_name,
            )

            logger.info("Merged %d adapters into '%s'", len(adapter_names), new_adapter_name)
            return True

        except Exception as e:
            logger.exception("Failed to merge adapters: %s", e)
            return False

    def compare_adapter_configs(
        self,
        config1_path: str | Path,
        config2_path: str | Path,
    ) -> dict[str, Any]:
        """Compare two PEFT adapter configurations.

        Args:
            config1_path: Path to first adapter config
            config2_path: Path to second adapter config

        Returns:
            Comparison results with differences

        """
        results: dict[str, Any] = {
            "compatible": True,
            "differences": [],
            "config1_details": {},
            "config2_details": {},
        }

        if not HAS_PEFT or PeftConfig is None:
            results["compatible"] = False
            if isinstance(results["differences"], list):
                results["differences"].append("PEFT not available for comparison")
            return results

        try:
            config1: Any = PeftConfig.from_json_file(str(config1_path))
            config2: Any = PeftConfig.from_json_file(str(config2_path))

            if config1.peft_type != config2.peft_type:
                results["compatible"] = False
                if isinstance(results["differences"], list):
                    results["differences"].append(
                        f"Different PEFT types: {config1.peft_type} vs {config2.peft_type}",
                    )

            params_to_compare: list[str] = ["r", "lora_alpha", "lora_dropout", "target_modules", "task_type"]

            for param in params_to_compare:
                val1: Any = getattr(config1, param, None)
                val2: Any = getattr(config2, param, None)

                if val1 != val2:
                    if isinstance(results["differences"], list):
                        results["differences"].append(
                            f"Different {param}: {val1} vs {val2}",
                        )

                    if param in ["r", "lora_alpha"]:
                        pass
                    elif param == "target_modules":
                        results["compatible"] = False

            for attr in dir(config1):
                if not attr.startswith("_"):
                    try:
                        val: Any = getattr(config1, attr)
                        if not callable(val) and isinstance(results["config1_details"], dict):
                            results["config1_details"][attr] = str(val)
                    except (AttributeError, ValueError, TypeError):
                        pass

            for attr in dir(config2):
                if not attr.startswith("_"):
                    try:
                        val_: Any = getattr(config2, attr)
                        if not callable(val_) and isinstance(results["config2_details"], dict):
                            results["config2_details"][attr] = str(val_)
                    except (AttributeError, ValueError, TypeError):
                        pass

        except Exception as e:
            results["compatible"] = False
            if isinstance(results["differences"], list):
                results["differences"].append(f"Error comparing configs: {e}")

        return results

    def download_adapter(
        self,
        adapter_id: str,
        cache_dir: str | Path | None = None,
        revision: str | None = None,
    ) -> Path | None:
        """Download a LoRA adapter from Hugging Face Hub.

        Args:
            adapter_id: Hugging Face model ID
            cache_dir: Local cache directory
            revision: Specific revision to download

        Returns:
            Path to downloaded adapter or None

        """
        try:
            from huggingface_hub import snapshot_download

            resolved_cache_dir: Path
            if cache_dir is None:
                resolved_cache_dir = self.cache_dir / "downloads"
            else:
                resolved_cache_dir = Path(cache_dir) if isinstance(cache_dir, str) else cache_dir

            local_path: str = snapshot_download(
                repo_id=adapter_id,
                cache_dir=str(resolved_cache_dir),
                revision=revision,
            )

            logger.info("Downloaded adapter: %s", adapter_id)
            return Path(local_path)

        except ImportError:
            logger.exception("huggingface_hub required for adapter downloads")
            return None
        except Exception as e:
            logger.exception("Failed to download adapter: %s", e)
            return None

    def get_adapter_info(self, adapter_path: str | Path) -> dict[str, Any]:
        """Get information about a LoRA adapter.

        Args:
            adapter_path: Path to adapter

        Returns:
            Dictionary with adapter information

        """
        resolved_adapter_path: Path = Path(adapter_path)
        info: dict[str, Any] = {
            "path": str(resolved_adapter_path),
            "exists": resolved_adapter_path.exists(),
            "config": None,
            "peft_config": None,
            "size_mb": 0,
            "adapter_type": None,
            "target_modules": None,
        }

        if not resolved_adapter_path.exists():
            return info

        config_path: Path = resolved_adapter_path / "adapter_config.json"
        if config_path.exists():
            try:
                with open(config_path) as f:
                    info["config"] = json.load(f)

                if HAS_PEFT and PeftConfig is not None:
                    try:
                        peft_config: Any = PeftConfig.from_json_file(str(config_path))
                        info["peft_config"] = peft_config
                        info["adapter_type"] = peft_config.peft_type
                        if hasattr(peft_config, "target_modules"):
                            info["target_modules"] = peft_config.target_modules
                        logger.debug("Loaded PeftConfig for adapter: %s", resolved_adapter_path)
                    except Exception as e:
                        logger.debug("Could not parse as PeftConfig: %s", e)
            except Exception as e:
                logger.debug("Could not load adapter config: %s", e)

        total_size: int = sum(file.stat().st_size for file in resolved_adapter_path.rglob("*.bin"))
        for file in resolved_adapter_path.rglob("*.safetensors"):
            total_size += file.stat().st_size

        info["size_mb"] = total_size / (1024 * 1024)

        return info

    def validate_adapter_config(self, config_path: str | Path) -> dict[str, Any]:
        """Validate a PEFT adapter configuration file.

        Args:
            config_path: Path to adapter_config.json

        Returns:
            Validation results with any issues found

        """
        resolved_config_path: Path = Path(config_path)
        results: dict[str, Any] = {
            "valid": False,
            "errors": [],
            "warnings": [],
            "config_details": {},
        }

        if not resolved_config_path.exists():
            if isinstance(results["errors"], list):
                results["errors"].append(f"Config file not found: {resolved_config_path}")
            return results

        if not HAS_PEFT or PeftConfig is None:
            if isinstance(results["warnings"], list):
                results["warnings"].append("PEFT not available for full validation")
            try:
                with open(resolved_config_path) as f:
                    config_data: Any = json.load(f)
                results["config_details"] = config_data
                results["valid"] = True
            except Exception as e:
                if isinstance(results["errors"], list):
                    results["errors"].append(f"Invalid JSON: {e}")
            return results

        try:
            peft_config: Any = PeftConfig.from_json_file(str(resolved_config_path))

            if hasattr(peft_config, "peft_type"):
                if isinstance(results["config_details"], dict):
                    results["config_details"]["peft_type"] = peft_config.peft_type

            elif isinstance(results["errors"], list):
                results["errors"].append("Missing peft_type in config")
            if hasattr(peft_config, "r"):
                if isinstance(results["config_details"], dict):
                    results["config_details"]["rank"] = peft_config.r
                if peft_config.r > 64 and isinstance(results["warnings"], list):
                    results["warnings"].append(f"Very high LoRA rank ({peft_config.r}) may use excessive memory")

            if hasattr(peft_config, "target_modules"):
                if isinstance(results["config_details"], dict):
                    results["config_details"]["target_modules"] = peft_config.target_modules
                if not peft_config.target_modules and isinstance(results["warnings"], list):
                    results["warnings"].append("No target modules specified")

            if hasattr(peft_config, "task_type") and isinstance(results["config_details"], dict):
                results["config_details"]["task_type"] = str(peft_config.task_type)

            if hasattr(peft_config, "base_model_name_or_path") and isinstance(results["config_details"], dict):
                results["config_details"]["base_model"] = peft_config.base_model_name_or_path

            errors_list = results["errors"]
            if isinstance(errors_list, list):
                results["valid"] = len(errors_list) == 0

        except Exception as e:
            if isinstance(results["errors"], list):
                results["errors"].append(f"Failed to parse PeftConfig: {e}")

        return results

    def cleanup_cache(self, keep_recent: int = 5) -> None:
        """Clean up cached adapters, keeping only recent ones.

        Args:
            keep_recent: Number of recent adapters to keep

        """
        if len(self.loaded_adapters) <= keep_recent:
            return

        # Sort by access time (would need to track this)
        # For now, just clear oldest entries
        to_remove = len(self.loaded_adapters) - keep_recent
        for key in list(self.loaded_adapters)[:to_remove]:
            del self.loaded_adapters[key]

        logger.info("Cleaned up adapter cache, kept %d recent adapters", keep_recent)


# Global instance
_ADAPTER_MANAGER = None


def get_adapter_manager() -> LoRAAdapterManager:
    """Get the global LoRA adapter manager.

    Returns:
        LoRAAdapterManager: The singleton instance of the global LoRA adapter manager.

    """
    global _ADAPTER_MANAGER
    if _ADAPTER_MANAGER is None:
        _ADAPTER_MANAGER = LoRAAdapterManager()
    return _ADAPTER_MANAGER
