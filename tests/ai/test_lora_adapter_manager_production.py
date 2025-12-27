"""Production tests for LoRA adapter manager.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.lora_adapter_manager import (
    AdapterConfig,
    LoRAAdapterManager,
    get_adapter_manager,
)


class TestLoRAAdapterManager:
    """Test LoRA adapter manager functionality."""

    @pytest.fixture
    def temp_cache_dir(self) -> Path:
        """Create temporary cache directory."""
        temp_dir = tempfile.mkdtemp(prefix="lora_test_")
        cache_path = Path(temp_dir)
        yield cache_path
        import shutil
        shutil.rmtree(cache_path, ignore_errors=True)

    @pytest.fixture
    def adapter_manager(self, temp_cache_dir: Path) -> LoRAAdapterManager:
        """Create LoRA adapter manager with temp cache."""
        return LoRAAdapterManager(cache_dir=temp_cache_dir)

    @pytest.fixture
    def mock_adapter_config(self, temp_cache_dir: Path) -> Path:
        """Create mock adapter config file."""
        adapter_dir = temp_cache_dir / "test_adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)

        config_data = {
            "peft_type": "LORA",
            "r": 16,
            "lora_alpha": 32,
            "target_modules": ["q_proj", "v_proj"],
            "lora_dropout": 0.1,
            "bias": "none",
            "task_type": "CAUSAL_LM",
            "base_model_name_or_path": "test/model"
        }

        config_path = adapter_dir / "adapter_config.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        return config_path

    def test_adapter_manager_initialization(self, temp_cache_dir: Path) -> None:
        """Adapter manager initializes with correct cache directory."""
        manager = LoRAAdapterManager(cache_dir=temp_cache_dir)

        assert manager.cache_dir == temp_cache_dir
        assert temp_cache_dir.exists()
        assert isinstance(manager.loaded_adapters, dict)
        assert isinstance(manager.adapter_configs, dict)
        assert len(manager.loaded_adapters) == 0

    def test_adapter_manager_default_cache_dir(self) -> None:
        """Adapter manager uses default cache directory when none specified."""
        manager = LoRAAdapterManager()

        expected_dir = Path.home() / ".intellicrack" / "lora_adapters"
        assert manager.cache_dir == expected_dir
        assert expected_dir.exists()

    def test_get_default_target_modules_llama(self, adapter_manager: LoRAAdapterManager) -> None:
        """Default target modules for LLaMA architecture are correct."""
        modules = adapter_manager._get_default_target_modules("llama")

        assert isinstance(modules, list)
        assert len(modules) == 7
        assert "q_proj" in modules
        assert "v_proj" in modules
        assert "k_proj" in modules
        assert "o_proj" in modules
        assert "gate_proj" in modules
        assert "down_proj" in modules
        assert "up_proj" in modules

    def test_get_default_target_modules_gpt2(self, adapter_manager: LoRAAdapterManager) -> None:
        """Default target modules for GPT-2 architecture are correct."""
        modules = adapter_manager._get_default_target_modules("gpt2")

        assert isinstance(modules, list)
        assert len(modules) == 3
        assert "c_attn" in modules
        assert "c_proj" in modules
        assert "c_fc" in modules

    def test_get_default_target_modules_unknown(self, adapter_manager: LoRAAdapterManager) -> None:
        """Default target modules for unknown architecture returns fallback."""
        modules = adapter_manager._get_default_target_modules("unknown_arch")

        assert isinstance(modules, list)
        assert len(modules) == 4
        assert "q_proj" in modules
        assert "v_proj" in modules
        assert "k_proj" in modules
        assert "o_proj" in modules

    def test_get_adapter_info_valid_adapter(self, adapter_manager: LoRAAdapterManager, mock_adapter_config: Path) -> None:
        """Adapter info extraction works for valid adapter."""
        adapter_dir = mock_adapter_config.parent

        adapter_bin = adapter_dir / "adapter_model.bin"
        adapter_bin.write_bytes(b"x" * 1024 * 100)

        info = adapter_manager.get_adapter_info(adapter_dir)

        assert info["path"] == str(adapter_dir)
        assert info["exists"] is True
        assert info["config"] is not None
        assert info["config"]["peft_type"] == "LORA"
        assert info["config"]["r"] == 16
        assert info["size_mb"] > 0

    def test_get_adapter_info_nonexistent(self, adapter_manager: LoRAAdapterManager, temp_cache_dir: Path) -> None:
        """Adapter info for nonexistent path returns correct status."""
        nonexistent = temp_cache_dir / "nonexistent_adapter"

        info = adapter_manager.get_adapter_info(nonexistent)

        assert info["path"] == str(nonexistent)
        assert info["exists"] is False
        assert info["config"] is None
        assert info["size_mb"] == 0

    def test_validate_adapter_config_valid(self, adapter_manager: LoRAAdapterManager, mock_adapter_config: Path) -> None:
        """Adapter config validation passes for valid config."""
        results = adapter_manager.validate_adapter_config(mock_adapter_config)

        assert results["valid"] is True
        assert isinstance(results["errors"], list)
        assert len(results["errors"]) == 0
        assert isinstance(results["warnings"], list)
        assert isinstance(results["config_details"], dict)

    def test_validate_adapter_config_nonexistent(self, adapter_manager: LoRAAdapterManager, temp_cache_dir: Path) -> None:
        """Adapter config validation fails for nonexistent config."""
        nonexistent = temp_cache_dir / "nonexistent.json"

        results = adapter_manager.validate_adapter_config(nonexistent)

        assert results["valid"] is False
        assert isinstance(results["errors"], list)
        assert len(results["errors"]) > 0
        assert "not found" in results["errors"][0].lower()

    def test_validate_adapter_config_malformed_json(self, adapter_manager: LoRAAdapterManager, temp_cache_dir: Path) -> None:
        """Adapter config validation fails for malformed JSON."""
        malformed_config = temp_cache_dir / "malformed.json"
        malformed_config.write_text("{ invalid json }")

        results = adapter_manager.validate_adapter_config(malformed_config)

        assert results["valid"] is False
        assert isinstance(results["errors"], list)
        assert len(results["errors"]) > 0

    def test_validate_adapter_config_high_rank_warning(self, adapter_manager: LoRAAdapterManager, temp_cache_dir: Path) -> None:
        """Adapter config validation warns about very high rank."""
        high_rank_config = temp_cache_dir / "high_rank.json"
        config_data = {
            "peft_type": "LORA",
            "r": 128,
            "lora_alpha": 256,
            "target_modules": ["q_proj"],
            "task_type": "CAUSAL_LM"
        }

        with open(high_rank_config, "w") as f:
            json.dump(config_data, f)

        results = adapter_manager.validate_adapter_config(high_rank_config)

        assert isinstance(results["warnings"], list)
        has_rank_warning = any("rank" in w.lower() for w in results["warnings"])
        assert has_rank_warning

    def test_compare_adapter_configs_identical(self, adapter_manager: LoRAAdapterManager, temp_cache_dir: Path) -> None:
        """Comparing identical adapter configs shows compatibility."""
        config_data = {
            "peft_type": "LORA",
            "r": 16,
            "lora_alpha": 32,
            "target_modules": ["q_proj", "v_proj"],
            "task_type": "CAUSAL_LM"
        }

        config1 = temp_cache_dir / "config1.json"
        config2 = temp_cache_dir / "config2.json"

        with open(config1, "w") as f:
            json.dump(config_data, f)
        with open(config2, "w") as f:
            json.dump(config_data, f)

        results = adapter_manager.compare_adapter_configs(config1, config2)

        assert results["compatible"] is True
        assert isinstance(results["differences"], list)

    def test_compare_adapter_configs_different_types(self, adapter_manager: LoRAAdapterManager, temp_cache_dir: Path) -> None:
        """Comparing configs with different PEFT types shows incompatibility."""
        config1_data = {"peft_type": "LORA", "r": 16}
        config2_data = {"peft_type": "ADALORA", "r": 16}

        config1 = temp_cache_dir / "config1.json"
        config2 = temp_cache_dir / "config2.json"

        with open(config1, "w") as f:
            json.dump(config1_data, f)
        with open(config2, "w") as f:
            json.dump(config2_data, f)

        results = adapter_manager.compare_adapter_configs(config1, config2)

        assert results["compatible"] is False
        assert isinstance(results["differences"], list)
        has_type_diff = any("peft type" in d.lower() for d in results["differences"])
        assert has_type_diff

    def test_compare_adapter_configs_different_target_modules(self, adapter_manager: LoRAAdapterManager, temp_cache_dir: Path) -> None:
        """Comparing configs with different target modules shows incompatibility."""
        config1_data = {
            "peft_type": "LORA",
            "r": 16,
            "target_modules": ["q_proj", "v_proj"]
        }
        config2_data = {
            "peft_type": "LORA",
            "r": 16,
            "target_modules": ["q_proj", "k_proj"]
        }

        config1 = temp_cache_dir / "config1.json"
        config2 = temp_cache_dir / "config2.json"

        with open(config1, "w") as f:
            json.dump(config1_data, f)
        with open(config2, "w") as f:
            json.dump(config2_data, f)

        results = adapter_manager.compare_adapter_configs(config1, config2)

        assert results["compatible"] is False

    def test_cleanup_cache_keeps_recent(self, adapter_manager: LoRAAdapterManager) -> None:
        """Cache cleanup keeps specified number of recent adapters."""
        for i in range(10):
            adapter_manager.loaded_adapters[f"adapter_{i}"] = f"model_{i}"

        assert len(adapter_manager.loaded_adapters) == 10

        adapter_manager.cleanup_cache(keep_recent=5)

        assert len(adapter_manager.loaded_adapters) == 5

    def test_cleanup_cache_no_cleanup_needed(self, adapter_manager: LoRAAdapterManager) -> None:
        """Cache cleanup does nothing when under limit."""
        for i in range(3):
            adapter_manager.loaded_adapters[f"adapter_{i}"] = f"model_{i}"

        adapter_manager.cleanup_cache(keep_recent=5)

        assert len(adapter_manager.loaded_adapters) == 3


class TestAdapterConfig:
    """Test AdapterConfig dataclass."""

    def test_adapter_config_defaults(self) -> None:
        """AdapterConfig has correct default values."""
        config = AdapterConfig(adapter_type="lora")

        assert config.adapter_type == "lora"
        assert config.r == 16
        assert config.lora_alpha == 32
        assert config.target_modules is None
        assert config.lora_dropout == 0.1
        assert config.bias == "none"
        assert config.task_type == "CAUSAL_LM"
        assert config.inference_mode is True
        assert config.fan_in_fan_out is False
        assert config.modules_to_save is None

    def test_adapter_config_custom_values(self) -> None:
        """AdapterConfig accepts custom values."""
        config = AdapterConfig(
            adapter_type="adalora",
            r=32,
            lora_alpha=64,
            target_modules=["q_proj", "v_proj", "k_proj"],
            lora_dropout=0.2,
            bias="all",
            task_type="SEQ_2_SEQ_LM",
            inference_mode=False
        )

        assert config.adapter_type == "adalora"
        assert config.r == 32
        assert config.lora_alpha == 64
        assert config.target_modules == ["q_proj", "v_proj", "k_proj"]
        assert config.lora_dropout == 0.2
        assert config.bias == "all"
        assert config.task_type == "SEQ_2_SEQ_LM"
        assert config.inference_mode is False


class TestGlobalAdapterManager:
    """Test global adapter manager singleton."""

    def test_get_adapter_manager_singleton(self) -> None:
        """Global adapter manager returns same instance."""
        manager1 = get_adapter_manager()
        manager2 = get_adapter_manager()

        assert manager1 is manager2
        assert isinstance(manager1, LoRAAdapterManager)

    def test_get_adapter_manager_initialization(self) -> None:
        """Global adapter manager is properly initialized."""
        manager = get_adapter_manager()

        assert manager.cache_dir is not None
        assert manager.cache_dir.exists()
        assert isinstance(manager.loaded_adapters, dict)
        assert isinstance(manager.adapter_configs, dict)


class TestAdapterManagerEdgeCases:
    """Test edge cases and error handling."""

    @pytest.fixture
    def adapter_manager(self) -> LoRAAdapterManager:
        """Create adapter manager for edge case testing."""
        temp_dir = tempfile.mkdtemp(prefix="lora_edge_")
        manager = LoRAAdapterManager(cache_dir=temp_dir)
        yield manager
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    def test_get_adapter_info_permission_error_handling(self, adapter_manager: LoRAAdapterManager, tmp_path: Path) -> None:
        """Adapter info handles permission errors gracefully."""
        adapter_dir = tmp_path / "protected_adapter"
        adapter_dir.mkdir()

        info = adapter_manager.get_adapter_info(adapter_dir)

        assert info["exists"] is True
        assert info["size_mb"] == 0

    def test_validate_empty_config(self, adapter_manager: LoRAAdapterManager, tmp_path: Path) -> None:
        """Adapter config validation handles empty JSON."""
        empty_config = tmp_path / "empty.json"
        empty_config.write_text("{}")

        results = adapter_manager.validate_adapter_config(empty_config)

        assert isinstance(results, dict)
        assert "valid" in results
        assert "errors" in results

    def test_get_adapter_info_with_multiple_file_types(self, adapter_manager: LoRAAdapterManager, tmp_path: Path) -> None:
        """Adapter info calculates size for multiple weight file formats."""
        adapter_dir = tmp_path / "multi_format_adapter"
        adapter_dir.mkdir()

        config_data = {"peft_type": "LORA", "r": 8}
        config_path = adapter_dir / "adapter_config.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)

        (adapter_dir / "adapter_model.bin").write_bytes(b"x" * 1024 * 50)
        (adapter_dir / "adapter_model.safetensors").write_bytes(b"x" * 1024 * 75)

        info = adapter_manager.get_adapter_info(adapter_dir)

        assert info["size_mb"] > 0.1
        assert info["exists"] is True

    def test_compare_configs_with_missing_fields(self, adapter_manager: LoRAAdapterManager, tmp_path: Path) -> None:
        """Comparing configs with missing fields handles gracefully."""
        config1_data = {"peft_type": "LORA", "r": 16}
        config2_data = {"peft_type": "LORA"}

        config1 = tmp_path / "config1.json"
        config2 = tmp_path / "config2.json"

        with open(config1, "w") as f:
            json.dump(config1_data, f)
        with open(config2, "w") as f:
            json.dump(config2_data, f)

        results = adapter_manager.compare_adapter_configs(config1, config2)

        assert isinstance(results, dict)
        assert "compatible" in results
        assert "differences" in results
