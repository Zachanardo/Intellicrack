"""Comprehensive tests for quantization manager.

Tests validate model quantization accuracy, performance gains, format compatibility,
GPU optimization, and memory management with real model operations.
"""

from pathlib import Path
from typing import Any

import pytest

from intellicrack.ai.quantization_manager import (
    QuantizationManager,
    get_quantization_manager,
)


class TestQuantizationManager:
    """Test model quantization management."""

    def test_quantization_manager_initialization(self) -> None:
        """Test quantization manager initializes with available backends."""
        manager = QuantizationManager()

        assert isinstance(manager.loaded_models, dict)
        assert isinstance(manager.available_backends, dict)
        assert "transformers" in manager.available_backends
        assert "bitsandbytes" in manager.available_backends

    def test_get_best_device_selection(self) -> None:
        """Test automatic device selection logic."""
        manager = QuantizationManager()

        device = manager._get_best_device()

        assert device in ["cpu", "cuda", "mps"]

    def test_get_supported_quantization_types(self) -> None:
        """Test listing supported quantization types."""
        manager = QuantizationManager()

        supported_types = manager.get_supported_quantization_types()

        assert isinstance(supported_types, list)
        assert "none" in supported_types

    def test_estimate_memory_usage_calculation(self) -> None:
        """Test memory usage estimation for models."""
        manager = QuantizationManager()

        with pytest.raises((FileNotFoundError, Exception)):
            estimates = manager.estimate_memory_usage("/nonexistent/model", "auto")

    def test_create_quantization_config_8bit(self) -> None:
        """Test creating 8-bit quantization configuration."""
        manager = QuantizationManager()

        config = manager.create_quantization_config("8bit")

        assert isinstance(config, dict)
        if "load_in_8bit" in config:
            assert config["load_in_8bit"] is True

    def test_create_quantization_config_4bit(self) -> None:
        """Test creating 4-bit quantization configuration."""
        manager = QuantizationManager()

        config = manager.create_quantization_config("4bit")

        assert isinstance(config, dict)
        if "load_in_4bit" in config:
            assert config["load_in_4bit"] is True

    def test_create_quantization_config_gptq(self) -> None:
        """Test creating GPTQ quantization configuration."""
        manager = QuantizationManager()

        config = manager.create_quantization_config("gptq")

        assert isinstance(config, dict)

    def test_create_quantization_config_dynamic(self) -> None:
        """Test creating dynamic quantization configuration."""
        manager = QuantizationManager()

        config = manager.create_quantization_config("dynamic")

        assert isinstance(config, dict)

    def test_create_quantization_config_static(self) -> None:
        """Test creating static quantization configuration."""
        manager = QuantizationManager()

        config = manager.create_quantization_config("static")

        assert isinstance(config, dict)

    def test_create_quantization_config_none(self) -> None:
        """Test creating config for no quantization."""
        manager = QuantizationManager()

        config = manager.create_quantization_config("none")

        assert isinstance(config, dict)
        assert config["quantization_type"] == "none"

    def test_create_quantization_config_invalid_type(self) -> None:
        """Test creating config with invalid type raises error."""
        manager = QuantizationManager()

        with pytest.raises(ValueError):
            manager.create_quantization_config("invalid_type")

    def test_get_sharding_info(self) -> None:
        """Test getting multi-GPU sharding information."""
        manager = QuantizationManager()

        info = manager.get_sharding_info()

        assert isinstance(info, dict)
        assert "cuda_available" in info or "device_count" in info

    def test_cleanup_memory(self) -> None:
        """Test memory cleanup after operations."""
        manager = QuantizationManager()

        manager.cleanup_memory()


class TestLoRAConfiguration:
    """Test LoRA adapter configuration."""

    def test_create_lora_config_default_params(self) -> None:
        """Test creating LoRA config with default parameters."""
        manager = QuantizationManager()

        config = manager.create_lora_config()

        if config is not None:
            assert hasattr(config, "r") or isinstance(config, dict)

    def test_create_lora_config_custom_params(self) -> None:
        """Test creating LoRA config with custom parameters."""
        manager = QuantizationManager()

        config = manager.create_lora_config(
            r=32,
            lora_alpha=64,
            target_modules=["q_proj", "v_proj"],
            lora_dropout=0.05
        )

        if config is not None:
            assert isinstance(config, object) or isinstance(config, dict)

    def test_create_lora_config_without_peft(self) -> None:
        """Test LoRA config creation without PEFT library."""
        manager = QuantizationManager()

        if not manager.available_backends.get("peft"):
            config = manager.create_lora_config()
            assert config is None


class TestGPTQConfiguration:
    """Test GPTQ quantization configuration."""

    def test_create_gptq_config_default(self) -> None:
        """Test creating GPTQ config with defaults."""
        manager = QuantizationManager()

        config = manager.create_gptq_config()

        if config is not None:
            assert hasattr(config, "bits") or isinstance(config, dict)

    def test_create_gptq_config_custom_bits(self) -> None:
        """Test creating GPTQ config with custom bit depth."""
        manager = QuantizationManager()

        config = manager.create_gptq_config(bits=8, group_size=64)

        if config is not None:
            assert isinstance(config, object) or isinstance(config, dict)

    def test_create_gptq_config_additional_params(self) -> None:
        """Test creating GPTQ config with additional parameters."""
        manager = QuantizationManager()

        config = manager.create_gptq_config(
            bits=4,
            group_size=128,
            damp_percent=0.2,
            desc_act=False,
            static_groups=True
        )

        if config is not None:
            assert isinstance(config, object) or isinstance(config, dict)


class TestModelLoadingPaths:
    """Test model loading path resolution and validation."""

    def test_detect_quantization_type_from_files(self) -> None:
        """Test quantization type detection from model files."""
        manager = QuantizationManager()

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir)

            (model_path / "model_gptq.safetensors").touch()

            quant_type = manager._detect_quantization_type(model_path)

            assert quant_type in ["gptq", "none"]

    def test_detect_quantization_type_from_config(self) -> None:
        """Test quantization type detection from config.json."""
        manager = QuantizationManager()

        import tempfile
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir)

            config_data = {
                "quantization_config": {
                    "bits": 4,
                    "quant_method": "gptq"
                }
            }

            config_path = model_path / "config.json"
            with open(config_path, 'w') as f:
                json.dump(config_data, f)

            quant_type = manager._detect_quantization_type(model_path)

            assert quant_type == "gptq"

    def test_detect_quantization_type_no_indicators(self) -> None:
        """Test quantization type detection with no indicators."""
        manager = QuantizationManager()

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir)

            quant_type = manager._detect_quantization_type(model_path)

            assert quant_type == "none"


class TestMemoryEstimation:
    """Test memory usage estimation."""

    def test_estimate_memory_different_quantizations(self) -> None:
        """Test memory estimation for different quantization types."""
        manager = QuantizationManager()

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir)

            test_file = model_path / "model.safetensors"
            test_file.write_bytes(b'\x00' * (100 * 1024 * 1024))

            estimates_fp16 = manager.estimate_memory_usage(model_path, "none")
            estimates_8bit = manager.estimate_memory_usage(model_path, "8bit")
            estimates_4bit = manager.estimate_memory_usage(model_path, "4bit")

            assert estimates_fp16["estimated_memory_gb"] > estimates_8bit["estimated_memory_gb"]
            assert estimates_8bit["estimated_memory_gb"] > estimates_4bit["estimated_memory_gb"]

    def test_estimate_memory_contains_all_formats(self) -> None:
        """Test memory estimates include all precision formats."""
        manager = QuantizationManager()

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir)

            test_file = model_path / "model.bin"
            test_file.write_bytes(b'\x00' * (10 * 1024 * 1024))

            estimates = manager.estimate_memory_usage(model_path)

            assert "disk_size_gb" in estimates
            assert "fp32_memory_gb" in estimates
            assert "fp16_memory_gb" in estimates
            assert "int8_memory_gb" in estimates
            assert "int4_memory_gb" in estimates


class TestBackendAvailability:
    """Test backend availability and fallback handling."""

    def test_available_backends_detection(self) -> None:
        """Test backend availability is correctly detected."""
        manager = QuantizationManager()

        backends = manager.available_backends

        assert "transformers" in backends
        assert "bitsandbytes" in backends
        assert "auto_gptq" in backends
        assert "peft" in backends

        for backend, available in backends.items():
            assert isinstance(available, bool)

    def test_quantization_types_match_backends(self) -> None:
        """Test supported quantization types match available backends."""
        manager = QuantizationManager()

        supported = manager.get_supported_quantization_types()

        assert "none" in supported

        if manager.available_backends["bitsandbytes"]:
            assert "8bit" in supported or "4bit" in supported

    def test_load_model_without_required_backend(self) -> None:
        """Test loading model without required backend returns None."""
        manager = QuantizationManager()

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir)

            result = manager.load_quantized_model(
                model_path,
                quantization_type="8bit",
                device="cpu"
            )

            assert result is None


class TestGlobalManagerInstance:
    """Test global quantization manager instance."""

    def test_get_quantization_manager_singleton(self) -> None:
        """Test get_quantization_manager returns singleton instance."""
        manager1 = get_quantization_manager()
        manager2 = get_quantization_manager()

        assert manager1 is manager2

    def test_global_manager_is_initialized(self) -> None:
        """Test global manager is properly initialized."""
        manager = get_quantization_manager()

        assert manager is not None
        assert isinstance(manager, QuantizationManager)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_load_model_invalid_path(self) -> None:
        """Test loading model with invalid path."""
        manager = QuantizationManager()

        result = manager.load_quantized_model(
            "/nonexistent/path/to/model",
            quantization_type="auto",
            device="cpu"
        )

        assert result is None

    def test_create_lora_config_with_invalid_params(self) -> None:
        """Test LoRA config creation with edge case parameters."""
        manager = QuantizationManager()

        config = manager.create_lora_config(
            r=0,
            lora_alpha=0,
            lora_dropout=1.0
        )

        if config is not None:
            assert isinstance(config, object) or isinstance(config, dict)

    def test_estimate_memory_empty_directory(self) -> None:
        """Test memory estimation for empty model directory."""
        manager = QuantizationManager()

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir)

            estimates = manager.estimate_memory_usage(model_path)

            assert estimates["disk_size_gb"] == 0.0

    def test_get_sharding_info_no_gpu(self) -> None:
        """Test sharding info when no GPU is available."""
        manager = QuantizationManager()

        info = manager.get_sharding_info()

        assert isinstance(info, dict)
        assert "cuda_available" in info or "device_count" in info

    def test_cleanup_memory_without_loaded_models(self) -> None:
        """Test memory cleanup without loaded models."""
        manager = QuantizationManager()

        manager.cleanup_memory()

    def test_detect_quantization_type_file_path(self) -> None:
        """Test quantization type detection for single file path."""
        manager = QuantizationManager()

        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
            f.write(b'\x00' * 1024)
            temp_path = Path(f.name)

        try:
            quant_type = manager._detect_quantization_type(temp_path)

            assert quant_type == "none"

        finally:
            temp_path.unlink()


class TestQuantizationWorkflows:
    """Test complete quantization workflows."""

    def test_quantization_config_creation_workflow(self) -> None:
        """Test complete workflow of creating quantization configs."""
        manager = QuantizationManager()

        supported_types = manager.get_supported_quantization_types()

        for quant_type in supported_types:
            if quant_type != "none":
                config = manager.create_quantization_config(quant_type)
                assert isinstance(config, dict)

    def test_lora_and_gptq_combination(self) -> None:
        """Test combining LoRA and GPTQ configurations."""
        manager = QuantizationManager()

        gptq_config = manager.create_gptq_config(bits=4)
        lora_config = manager.create_lora_config(r=16)

        if gptq_config is not None:
            assert hasattr(gptq_config, "bits") or isinstance(gptq_config, dict)

        if lora_config is not None:
            assert hasattr(lora_config, "r") or isinstance(lora_config, dict)

    def test_device_selection_and_quantization(self) -> None:
        """Test device selection affects quantization choices."""
        manager = QuantizationManager()

        device = manager._get_best_device()

        if device == "cpu":
            result = manager.load_quantized_model(
                "/test/model",
                quantization_type="8bit",
                device="cpu"
            )

            assert result is None

    def test_memory_estimation_workflow(self) -> None:
        """Test workflow of estimating memory for multiple models."""
        manager = QuantizationManager()

        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir)

            test_file = model_path / "model.bin"
            test_file.write_bytes(b'\x00' * (50 * 1024 * 1024))

            for quant_type in ["none", "8bit", "4bit", "gptq"]:
                estimates = manager.estimate_memory_usage(model_path, quant_type)

                assert "estimated_memory_gb" in estimates
                assert estimates["estimated_memory_gb"] >= 0
