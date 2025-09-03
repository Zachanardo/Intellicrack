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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..utils.logger import get_logger

logger = get_logger(__name__)

# Optional torch import
HAS_TORCH = False
try:
    import torch

    HAS_TORCH = True
except ImportError as e:
    logger.error("Import error in lora_adapter_manager: %s", e)
    torch = None

# Try to import PEFT
try:
    from peft import (
        AdaLoraConfig,
        LoraConfig,
        PeftConfig,
        PeftModel,
        TaskType,
        get_peft_model,
        prepare_model_for_kbit_training,
    )

    HAS_PEFT = True
except ImportError as e:
    logger.error("Import error in lora_adapter_manager: %s", e)
    AdaLoraConfig = None
    LoraConfig = None
    PeftConfig = None
    PeftModel = None
    TaskType = None
    get_peft_model = None
    prepare_model_for_kbit_training = None
    HAS_PEFT = False

try:
    from transformers import AutoModelForCausalLM, AutoTokenizer

    HAS_TRANSFORMERS = True
except ImportError as e:
    logger.error("Import error in lora_adapter_manager: %s", e)
    AutoModelForCausalLM = None
    AutoTokenizer = None
    HAS_TRANSFORMERS = False


@dataclass
class AdapterConfig:
    """Configuration for a LoRA/QLoRA adapter."""

    adapter_type: str  # "lora", "qlora", "adalora"
    r: int = 16  # LoRA rank
    lora_alpha: int = 32  # LoRA alpha parameter
    target_modules: list[str] = None  # Modules to apply LoRA to
    lora_dropout: float = 0.1  # Dropout rate
    bias: str = "none"  # Bias configuration
    task_type: str = "CAUSAL_LM"  # Task type
    inference_mode: bool = True  # Whether in inference mode
    fan_in_fan_out: bool = False  # For GPT-2 style models
    modules_to_save: list[str] = None  # Additional modules to save
    # AdaLoRA specific
    target_r: int = 8  # Target rank for AdaLoRA
    init_r: int = 12  # Initial rank for AdaLoRA


class LoRAAdapterManager:
    """Manages LoRA and QLoRA adapters for efficient fine-tuning."""

    def __init__(self, cache_dir: str | None = None):
        """Initialize the LoRA adapter manager.

        Args:
            cache_dir: Directory to cache downloaded adapters

        """
        if cache_dir is None:
            cache_dir = Path.home() / ".intellicrack" / "lora_adapters"

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.loaded_adapters = {}
        self.adapter_configs = {}

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
        **kwargs,
    ) -> Any | None:
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
            logger.error("PEFT required for LoRA configuration")
            return None

        # Default target modules for common architectures
        if target_modules is None:
            target_modules = self._get_default_target_modules(kwargs.get("model_type"))

        try:
            if adapter_type == "adalora":
                config = AdaLoraConfig(
                    r=r,
                    lora_alpha=lora_alpha,
                    target_modules=target_modules,
                    lora_dropout=lora_dropout,
                    bias=kwargs.get("bias", "none"),
                    task_type=kwargs.get("task_type", TaskType.CAUSAL_LM),
                    inference_mode=kwargs.get("inference_mode", False),
                    target_r=kwargs.get("target_r", 8),
                    init_r=kwargs.get("init_r", 12),
                )
            else:
                config = LoraConfig(
                    r=r,
                    lora_alpha=lora_alpha,
                    target_modules=target_modules,
                    lora_dropout=lora_dropout,
                    bias=kwargs.get("bias", "none"),
                    task_type=kwargs.get("task_type", TaskType.CAUSAL_LM),
                    inference_mode=kwargs.get("inference_mode", False),
                    fan_in_fan_out=kwargs.get("fan_in_fan_out", False),
                    modules_to_save=kwargs.get("modules_to_save"),
                )

            return config

        except Exception as e:
            logger.error(f"Failed to create LoRA config: {e}")
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
    ) -> Any | None:
        """Apply LoRA adapter to a model.

        Args:
            model: Base model
            lora_config: LoRA configuration
            adapter_name: Name for the adapter

        Returns:
            Model with LoRA adapter or None

        """
        if not HAS_PEFT:
            logger.error("PEFT required to apply LoRA")
            return None

        try:
            # Apply LoRA
            peft_model = get_peft_model(model, lora_config, adapter_name=adapter_name)

            # Log adapter information
            trainable_params = sum(p.numel() for p in peft_model.parameters() if p.requires_grad)
            total_params = sum(p.numel() for p in peft_model.parameters())

            logger.info(
                f"Applied LoRA adapter '{adapter_name}': "
                f"{trainable_params:,} trainable params / {total_params:,} total params "
                f"({100 * trainable_params / total_params:.2f}% trainable)",
            )

            return peft_model

        except Exception as e:
            logger.error(f"Failed to apply LoRA: {e}")
            return None

    def load_adapter(
        self,
        base_model: Any,
        adapter_path: str | Path,
        adapter_name: str = "default",
        **kwargs,
    ) -> Any | None:
        """Load a LoRA adapter from disk.

        Args:
            base_model: Base model to apply adapter to
            adapter_path: Path to adapter files
            adapter_name: Name for the adapter
            **kwargs: Additional arguments

        Returns:
            Model with loaded adapter or None

        """
        if not HAS_PEFT:
            logger.error("PEFT required to load adapters")
            return None

        try:
            adapter_path = Path(adapter_path)

            # Check if adapter exists in cache
            cache_key = f"{adapter_path}_{adapter_name}"
            if cache_key in self.loaded_adapters:
                logger.info(f"Using cached adapter: {adapter_name}")
                return self.loaded_adapters[cache_key]

            # Load adapter
            model = PeftModel.from_pretrained(
                base_model,
                str(adapter_path),
                adapter_name=adapter_name,
                torch_dtype=kwargs.get("torch_dtype", torch.float16),
                device_map=kwargs.get("device_map", "auto"),
                is_trainable=kwargs.get("is_trainable", False),
            )

            # Merge adapter if requested
            if kwargs.get("merge_adapter", False):
                model = model.merge_and_unload()
                logger.info(f"Merged adapter '{adapter_name}' into base model")

            # Cache the model
            self.loaded_adapters[cache_key] = model

            logger.info(f"Loaded LoRA adapter from {adapter_path}")
            return model

        except Exception as e:
            logger.error(f"Failed to load adapter: {e}")
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
            logger.error("PEFT required to save adapters")
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
                logger.info(f"Saved LoRA adapter to {save_path}")
                return True
            logger.error("Model does not support save_pretrained")
            return False

        except Exception as e:
            logger.error(f"Failed to save adapter: {e}")
            return False

    def prepare_model_for_qlora(
        self,
        model: Any,
        use_gradient_checkpointing: bool = True,
        gradient_checkpointing_kwargs: dict | None = None,
    ) -> Any:
        """Prepare a model for QLoRA training.

        Args:
            model: Quantized model
            use_gradient_checkpointing: Whether to use gradient checkpointing
            gradient_checkpointing_kwargs: Arguments for gradient checkpointing

        Returns:
            Prepared model

        """
        if not HAS_PEFT:
            logger.error("PEFT required for QLoRA preparation")
            return model

        try:
            # Prepare for k-bit training
            model = prepare_model_for_kbit_training(
                model,
                use_gradient_checkpointing=use_gradient_checkpointing,
                gradient_checkpointing_kwargs=gradient_checkpointing_kwargs,
            )

            logger.info("Prepared model for QLoRA training")
            return model

        except Exception as e:
            logger.error(f"Failed to prepare model for QLoRA: {e}")
            return model

    def list_adapters(self, model: Any) -> list[str]:
        """List all adapters loaded in a model.

        Args:
            model: PEFT model

        Returns:
            List of adapter names

        """
        if hasattr(model, "peft_config"):
            return list(model.peft_config.keys())
        return []

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
                logger.info(f"Activated adapter: {adapter_name}")
                return True
            logger.error("Model does not support multiple adapters")
            return False

        except Exception as e:
            logger.error(f"Failed to set adapter: {e}")
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
                logger.error("Model does not support adapter merging")
                return False

            if weights is None:
                weights = [1.0 / len(adapter_names)] * len(adapter_names)

            model.add_weighted_adapter(
                adapter_names,
                weights,
                new_adapter_name,
            )

            logger.info(f"Merged {len(adapter_names)} adapters into '{new_adapter_name}'")
            return True

        except Exception as e:
            logger.error(f"Failed to merge adapters: {e}")
            return False

    def compare_adapter_configs(self, config1_path: str | Path, config2_path: str | Path) -> dict[str, Any]:
        """Compare two PEFT adapter configurations.

        Args:
            config1_path: Path to first adapter config
            config2_path: Path to second adapter config

        Returns:
            Comparison results with differences

        """
        results = {
            "compatible": True,
            "differences": [],
            "config1_details": {},
            "config2_details": {},
        }

        if not HAS_PEFT or not PeftConfig:
            results["compatible"] = False
            results["differences"].append("PEFT not available for comparison")
            return results

        try:
            # Load both configs
            config1 = PeftConfig.from_json_file(str(config1_path))
            config2 = PeftConfig.from_json_file(str(config2_path))

            # Compare peft types
            if config1.peft_type != config2.peft_type:
                results["compatible"] = False
                results["differences"].append(
                    f"Different PEFT types: {config1.peft_type} vs {config2.peft_type}",
                )

            # Compare important parameters
            params_to_compare = ["r", "lora_alpha", "lora_dropout", "target_modules", "task_type"]

            for param in params_to_compare:
                val1 = getattr(config1, param, None)
                val2 = getattr(config2, param, None)

                if val1 != val2:
                    results["differences"].append(
                        f"Different {param}: {val1} vs {val2}",
                    )

                    # Some differences don't affect compatibility
                    if param in ["r", "lora_alpha"]:
                        # Different ranks/alphas are still compatible for merging
                        pass
                    elif param == "target_modules":
                        # Different target modules are incompatible
                        results["compatible"] = False

            # Extract details for both configs
            for attr in dir(config1):
                if not attr.startswith("_"):
                    try:
                        val = getattr(config1, attr)
                        if not callable(val):
                            results["config1_details"][attr] = str(val)
                    except (AttributeError, ValueError, TypeError):
                        pass

            for attr in dir(config2):
                if not attr.startswith("_"):
                    try:
                        val = getattr(config2, attr)
                        if not callable(val):
                            results["config2_details"][attr] = str(val)
                    except (AttributeError, ValueError, TypeError):
                        pass

        except Exception as e:
            results["compatible"] = False
            results["differences"].append(f"Error comparing configs: {e}")

        return results

    def download_adapter(
        self,
        adapter_id: str,
        cache_dir: str | None = None,
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

            if cache_dir is None:
                cache_dir = self.cache_dir / "downloads"

            local_path = snapshot_download(
                repo_id=adapter_id,
                cache_dir=cache_dir,
                revision=revision,
            )

            logger.info(f"Downloaded adapter: {adapter_id}")
            return Path(local_path)

        except ImportError:
            logger.error("huggingface_hub required for adapter downloads")
            return None
        except Exception as e:
            logger.error(f"Failed to download adapter: {e}")
            return None

    def get_adapter_info(self, adapter_path: str | Path) -> dict[str, Any]:
        """Get information about a LoRA adapter.

        Args:
            adapter_path: Path to adapter

        Returns:
            Dictionary with adapter information

        """
        adapter_path = Path(adapter_path)
        info = {
            "path": str(adapter_path),
            "exists": adapter_path.exists(),
            "config": None,
            "peft_config": None,
            "size_mb": 0,
            "adapter_type": None,
            "target_modules": None,
        }

        if not adapter_path.exists():
            return info

        # Load config if available
        config_path = adapter_path / "adapter_config.json"
        if config_path.exists():
            try:
                with open(config_path) as f:
                    info["config"] = json.load(f)

                # Try to parse as PeftConfig if PEFT is available
                if HAS_PEFT and PeftConfig:
                    try:
                        peft_config = PeftConfig.from_json_file(str(config_path))
                        info["peft_config"] = peft_config
                        info["adapter_type"] = peft_config.peft_type
                        if hasattr(peft_config, "target_modules"):
                            info["target_modules"] = peft_config.target_modules
                        logger.debug(f"Loaded PeftConfig for adapter: {adapter_path}")
                    except Exception as e:
                        logger.debug(f"Could not parse as PeftConfig: {e}")
            except Exception as e:
                logger.debug(f"Could not load adapter config: {e}")

        # Calculate total size
        total_size = 0
        for file in adapter_path.rglob("*.bin"):
            total_size += file.stat().st_size
        for file in adapter_path.rglob("*.safetensors"):
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
        config_path = Path(config_path)
        results = {
            "valid": False,
            "errors": [],
            "warnings": [],
            "config_details": {},
        }

        if not config_path.exists():
            results["errors"].append(f"Config file not found: {config_path}")
            return results

        if not HAS_PEFT or not PeftConfig:
            results["warnings"].append("PEFT not available for full validation")
            # Basic JSON validation only
            try:
                with open(config_path) as f:
                    config_data = json.load(f)
                results["config_details"] = config_data
                results["valid"] = True
            except Exception as e:
                results["errors"].append(f"Invalid JSON: {e}")
            return results

        try:
            # Load and validate using PeftConfig
            peft_config = PeftConfig.from_json_file(str(config_path))

            # Check required fields
            if not hasattr(peft_config, "peft_type"):
                results["errors"].append("Missing peft_type in config")
            else:
                results["config_details"]["peft_type"] = peft_config.peft_type

            if hasattr(peft_config, "r"):
                results["config_details"]["rank"] = peft_config.r
                if peft_config.r > 64:
                    results["warnings"].append(f"Very high LoRA rank ({peft_config.r}) may use excessive memory")

            if hasattr(peft_config, "target_modules"):
                results["config_details"]["target_modules"] = peft_config.target_modules
                if not peft_config.target_modules:
                    results["warnings"].append("No target modules specified")

            if hasattr(peft_config, "task_type"):
                results["config_details"]["task_type"] = str(peft_config.task_type)

            # Validate model compatibility if base model is specified
            if hasattr(peft_config, "base_model_name_or_path"):
                results["config_details"]["base_model"] = peft_config.base_model_name_or_path

            results["valid"] = len(results["errors"]) == 0

        except Exception as e:
            results["errors"].append(f"Failed to parse PeftConfig: {e}")

        return results

    def cleanup_cache(self, keep_recent: int = 5):
        """Clean up cached adapters, keeping only recent ones.

        Args:
            keep_recent: Number of recent adapters to keep

        """
        if len(self.loaded_adapters) <= keep_recent:
            return

        # Sort by access time (would need to track this)
        # For now, just clear oldest entries
        to_remove = len(self.loaded_adapters) - keep_recent
        for key in list(self.loaded_adapters.keys())[:to_remove]:
            del self.loaded_adapters[key]

        logger.info(f"Cleaned up adapter cache, kept {keep_recent} recent adapters")


# Global instance
_ADAPTER_MANAGER = None


def get_adapter_manager() -> LoRAAdapterManager:
    """Get the global LoRA adapter manager."""
    global _ADAPTER_MANAGER
    if _ADAPTER_MANAGER is None:
        _ADAPTER_MANAGER = LoRAAdapterManager()
    return _ADAPTER_MANAGER
