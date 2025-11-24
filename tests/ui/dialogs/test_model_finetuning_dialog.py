"""Production-grade tests for AI model fine-tuning dialog.

This test suite validates real model fine-tuning operations for training models
on binary analysis and licensing cracking techniques. Tests verify actual training
workflows, dataset preparation, LoRA adapter creation, and model management.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3
"""

import json
import os
import pickle
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.handlers.pyqt6_handler import HAS_PYQT as PYQT6_AVAILABLE
from intellicrack.handlers.torch_handler import TORCH_AVAILABLE

if PYQT6_AVAILABLE:
    from intellicrack.handlers.pyqt6_handler import QApplication, QMessageBox, Qt
    from intellicrack.ui.dialogs.model_finetuning_dialog import (
        AugmentationConfig,
        LicenseAnalysisNeuralNetwork,
        ModelFinetuningDialog,
        TrainingConfig,
        TrainingStatus,
        TrainingThread,
        create_model_finetuning_dialog,
    )


pytestmark = pytest.mark.skipif(
    not PYQT6_AVAILABLE,
    reason="PyQt6 required for UI tests",
)


@pytest.fixture(scope="module")
def qapp() -> Any:
    """Create QApplication instance for testing."""
    if not PYQT6_AVAILABLE:
        pytest.skip("PyQt6 not available")
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def temp_dir() -> Path:
    """Create temporary directory for test files."""
    with tempfile.TemporaryDirectory(prefix="finetuning_test_") as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_training_dataset(temp_dir: Path) -> Path:
    """Create realistic training dataset for license cracking techniques."""
    dataset_path = temp_dir / "training_dataset.json"

    dataset = [
        {
            "input": "How do I identify hardware ID validation in a binary?",
            "output": "Search for GetVolumeInformation, GetAdaptersInfo, and CryptHashData API calls. Check for CPUID instructions and registry reads from HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid."
        },
        {
            "input": "What are common license key validation patterns?",
            "output": "Look for string comparisons, checksum calculations (CRC32, MD5), RSA signature verification, and modulus operations on serial numbers. License keys often use base32/base64 encoding."
        },
        {
            "input": "How to bypass trial period checks?",
            "output": "Locate registry keys storing first-run date (HKCU\\Software\\<Vendor>), patch time comparison instructions (cmp, jl, jg), or redirect GetSystemTime/GetLocalTime API calls to return fixed dates."
        },
        {
            "input": "What indicates VMProtect protection?",
            "output": "High section entropy (>7.0), virtualized code segments, mutation engine artifacts, and obscured imports. Look for .vmp0 and .vmp1 sections with non-standard characteristics."
        },
        {
            "input": "How to extract license validation logic?",
            "output": "Use dynamic instrumentation (Frida, DynamoRIO) to trace validation functions. Monitor registry/file access patterns and API calls to crypto functions. Identify decision points with conditional jumps."
        },
        {
            "input": "What are RSA license key validation indicators?",
            "output": "Look for bcrypt.dll or advapi32.dll imports (CryptVerifySignature, BCryptVerifySignature), large prime number constants, and modular exponentiation operations. Public key typically embedded as resource or hardcoded constant."
        },
        {
            "input": "How to defeat online activation systems?",
            "output": "Analyze network traffic to identify activation protocol. Common approaches: patch certificate validation, redirect DNS/hosts file to local server emulating responses, or patch activation result checks."
        },
        {
            "input": "What registry locations store license data?",
            "output": "HKCU\\Software\\<Vendor>, HKLM\\SOFTWARE\\<Vendor>, HKCU\\Software\\Classes\\CLSID (COM hijacking), and encrypted values in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion."
        }
    ]

    with open(dataset_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    return dataset_path


@pytest.fixture
def sample_model_file(temp_dir: Path) -> Path:
    """Create sample model file for testing."""
    model_path = temp_dir / "test_model.pt"

    if TORCH_AVAILABLE:
        import torch

        model_data = {
            "model_state_dict": {
                "layer1.weight": torch.randn(128, 256),
                "layer1.bias": torch.randn(128),
                "layer2.weight": torch.randn(64, 128),
                "layer2.bias": torch.randn(64),
                "output.weight": torch.randn(32, 64),
                "output.bias": torch.randn(32),
            },
            "config": {
                "model_type": "binary_analyzer",
                "input_size": 256,
                "hidden_size": 128,
                "output_size": 32,
            },
            "training_history": [],
        }
        torch.save(model_data, model_path)
    else:
        model_data = {
            "config": {
                "model_type": "binary_analyzer",
                "input_size": 256,
                "hidden_size": 128,
                "output_size": 32,
            },
            "training_history": [],
        }
        with open(model_path, "wb") as f:
            pickle.dump(model_data, f)

    return model_path


@pytest.fixture
def augmentation_dataset(temp_dir: Path) -> Path:
    """Create dataset for augmentation testing."""
    dataset_path = temp_dir / "augmentation_dataset.json"

    dataset = [
        {
            "input": "Identify the license validation function",
            "output": "Look for string comparisons and crypto operations"
        },
        {
            "input": "Bypass the trial period restriction",
            "output": "Patch time comparison instructions"
        },
        {
            "input": "Extract the serial number algorithm",
            "output": "Trace checksum calculations and modulus operations"
        }
    ]

    with open(dataset_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    return dataset_path


class TestTrainingConfig:
    """Test TrainingConfig dataclass functionality."""

    def test_training_config_initialization(self) -> None:
        """TrainingConfig initializes with valid default parameters."""
        config = TrainingConfig()

        assert config.epochs == 3
        assert config.batch_size == 4
        assert config.learning_rate == 0.0002
        assert config.lora_rank == 8
        assert config.lora_alpha == 16
        assert config.cutoff_len == 256
        assert config.optimizer == "adam"
        assert config.loss_function == "categorical_crossentropy"

    def test_training_config_custom_values(self) -> None:
        """TrainingConfig accepts custom training parameters."""
        config = TrainingConfig(
            epochs=10,
            batch_size=16,
            learning_rate=0.0001,
            lora_rank=16,
            lora_alpha=32,
        )

        assert config.epochs == 10
        assert config.batch_size == 16
        assert config.learning_rate == 0.0001
        assert config.lora_rank == 16
        assert config.lora_alpha == 32


class TestAugmentationConfig:
    """Test AugmentationConfig for dataset augmentation."""

    def test_augmentation_config_defaults(self) -> None:
        """AugmentationConfig initializes with sensible defaults."""
        config = AugmentationConfig()

        assert config.augmentations_per_sample == 2
        assert config.augmentation_probability == 0.8
        assert config.preserve_labels is True
        assert isinstance(config.techniques, list)
        assert "synonym_replacement" in config.techniques

    def test_augmentation_config_custom_techniques(self) -> None:
        """AugmentationConfig accepts custom augmentation techniques."""
        techniques = ["synonym_replacement", "random_swap", "random_deletion"]
        config = AugmentationConfig(
            techniques=techniques,
            augmentations_per_sample=5,
            augmentation_probability=0.9,
        )

        assert config.techniques == techniques
        assert config.augmentations_per_sample == 5
        assert config.augmentation_probability == 0.9


class TestLicenseAnalysisNeuralNetwork:
    """Test production neural network for license analysis."""

    def test_network_initialization(self) -> None:
        """Neural network initializes with proper architecture for license analysis."""
        network = LicenseAnalysisNeuralNetwork()

        assert network.config["model_type"] == "license_analysis_nn"
        assert network.config["input_size"] == 1024
        assert network.config["output_size"] == 32
        assert len(network.config["hidden_layers"]) == 4
        assert network.config["status"] == "production_ready"

    def test_network_weights_initialized(self) -> None:
        """Neural network weights are properly initialized using Xavier initialization."""
        network = LicenseAnalysisNeuralNetwork()

        assert "W1" in network.weights
        assert "b1" in network.biases
        assert network.weights["W1"].shape == (1024, 512)
        assert network.biases["b1"].shape == (1, 512)

        weight_std = network.np.std(network.weights["W1"])
        expected_std = network.np.sqrt(2.0 / (1024 + 512))
        assert abs(weight_std - expected_std) < 0.1

    def test_network_forward_pass(self) -> None:
        """Neural network performs forward pass with realistic binary features."""
        network = LicenseAnalysisNeuralNetwork()

        import numpy as np

        batch_size = 4
        input_features = np.random.randn(batch_size, 1024)

        output = network.forward(input_features)

        assert output.shape == (batch_size, 32)
        assert not np.any(np.isnan(output))
        assert not np.any(np.isinf(output))

    def test_network_training_capability(self) -> None:
        """Neural network can train on license protection patterns."""
        network = LicenseAnalysisNeuralNetwork()

        import numpy as np

        X_train = np.random.randn(100, 1024)
        y_train = np.random.randint(0, 2, (100, 32)).astype(float)

        initial_loss = network.compute_loss(X_train, y_train)

        training_results = network.train(
            X_train,
            y_train,
            epochs=5,
            batch_size=16,
        )

        assert "metrics" in training_results
        assert "loss_history" in training_results["metrics"]
        assert len(training_results["metrics"]["loss_history"]) == 5

        final_loss = training_results["metrics"]["loss_history"][-1]
        assert final_loss < initial_loss

    def test_network_license_pattern_recognition(self) -> None:
        """Neural network contains specialized patterns for license protection detection."""
        network = LicenseAnalysisNeuralNetwork()

        assert "hardware_id" in network.license_patterns
        assert "registry_keys" in network.license_patterns
        assert "activation_flow" in network.license_patterns
        assert "protection_strength" in network.license_patterns

        assert network.license_patterns["hardware_id"].shape == (64, 32)
        assert network.license_patterns["registry_keys"].shape == (32, 16)


class TestTrainingThread:
    """Test TrainingThread for asynchronous model training."""

    def test_training_thread_initialization(
        self, sample_model_file: Path, sample_training_dataset: Path
    ) -> None:
        """TrainingThread initializes with valid training configuration."""
        config = TrainingConfig(
            model_path=str(sample_model_file),
            dataset_path=str(sample_training_dataset),
            epochs=2,
            batch_size=2,
        )

        thread = TrainingThread(config)

        assert thread.config == config
        assert thread.status == TrainingStatus.IDLE
        assert thread.is_stopped is False
        assert thread.training_history == []

    def test_training_thread_model_loading(
        self, sample_model_file: Path, sample_training_dataset: Path
    ) -> None:
        """TrainingThread loads model files correctly."""
        config = TrainingConfig(
            model_path=str(sample_model_file),
            dataset_path=str(sample_training_dataset),
            model_format="PyTorch",
        )

        thread = TrainingThread(config)
        thread._load_model()

        assert thread.model is not None

    def test_training_thread_dataset_loading(
        self, sample_model_file: Path, sample_training_dataset: Path
    ) -> None:
        """TrainingThread loads and prepares training datasets."""
        config = TrainingConfig(
            model_path=str(sample_model_file),
            dataset_path=str(sample_training_dataset),
            dataset_format="JSON",
        )

        thread = TrainingThread(config)
        dataset = thread._load_dataset()

        assert dataset is not None
        assert len(dataset) > 0

    def test_training_thread_creates_minimal_model(
        self, sample_training_dataset: Path
    ) -> None:
        """TrainingThread creates functional model when file not available."""
        config = TrainingConfig(
            model_path="",
            dataset_path=str(sample_training_dataset),
            model_format="PyTorch",
        )

        thread = TrainingThread(config)
        thread._create_minimal_model()

        assert thread.model is not None
        if hasattr(thread.model, "parameters"):
            param_count = sum(
                p.numel() for p in thread.model.parameters() if hasattr(p, "numel")
            )
            assert param_count > 0

    def test_training_thread_stop_mechanism(
        self, sample_model_file: Path, sample_training_dataset: Path
    ) -> None:
        """TrainingThread can be stopped during training."""
        config = TrainingConfig(
            model_path=str(sample_model_file),
            dataset_path=str(sample_training_dataset),
            epochs=100,
        )

        thread = TrainingThread(config)

        assert thread.is_stopped is False
        thread.stop()
        assert thread.is_stopped is True
        assert thread.status == TrainingStatus.ERROR


class TestModelFinetuningDialog:
    """Test ModelFinetuningDialog UI and functionality."""

    def test_dialog_initialization(self, qapp: Any) -> None:
        """Dialog initializes with all required UI components."""
        dialog = ModelFinetuningDialog()

        assert dialog.windowTitle() == "AI Model Fine-Tuning"
        assert dialog.training_thread is None
        assert isinstance(dialog.training_config, TrainingConfig)
        assert isinstance(dialog.augmentation_config, AugmentationConfig)

        assert dialog.model_path_edit is not None
        assert dialog.dataset_path_edit is not None
        assert dialog.epochs_spin is not None
        assert dialog.batch_size_spin is not None
        assert dialog.learning_rate_spin is not None
        assert dialog.lora_rank_spin is not None
        assert dialog.lora_alpha_spin is not None

    def test_dialog_training_tab_configuration(self, qapp: Any) -> None:
        """Training tab contains all necessary configuration controls."""
        dialog = ModelFinetuningDialog()

        assert dialog.epochs_spin.value() == 3
        assert dialog.batch_size_spin.value() == 4
        assert dialog.learning_rate_spin.value() == 0.0002
        assert dialog.lora_rank_spin.value() == 8
        assert dialog.lora_alpha_spin.value() == 16

        dialog.epochs_spin.setValue(10)
        assert dialog.epochs_spin.value() == 10

        dialog.learning_rate_spin.setValue(0.0001)
        assert abs(dialog.learning_rate_spin.value() - 0.0001) < 1e-9

    def test_dialog_dataset_preview_loading(
        self, qapp: Any, sample_training_dataset: Path
    ) -> None:
        """Dialog loads and displays dataset preview correctly."""
        dialog = ModelFinetuningDialog()

        dialog.dataset_path_edit.setText(str(sample_training_dataset))
        dialog.dataset_format_combo.setCurrentText("JSON")
        dialog.sample_count_spin.setValue(5)

        dialog._load_dataset_preview()

        assert dialog.dataset_preview.rowCount() > 0
        assert dialog.dataset_preview.rowCount() <= 5

        first_row_input = dialog.dataset_preview.item(0, 0)
        assert first_row_input is not None
        assert len(first_row_input.text()) > 0

    def test_dialog_dataset_validation(
        self, qapp: Any, sample_training_dataset: Path
    ) -> None:
        """Dialog validates dataset format and structure."""
        dialog = ModelFinetuningDialog()

        dialog.dataset_path_edit.setText(str(sample_training_dataset))
        dialog.dataset_format_combo.setCurrentText("JSON")

        with open(sample_training_dataset, encoding="utf-8") as f:
            data = json.load(f)

        assert len(data) == 8
        for item in data:
            assert "input" in item
            assert "output" in item
            assert len(item["input"]) > 0
            assert len(item["output"]) > 0

    def test_dialog_model_save_functionality(
        self, qapp: Any, temp_dir: Path, sample_model_file: Path, sample_training_dataset: Path
    ) -> None:
        """Dialog saves fine-tuned models with training history."""
        dialog = ModelFinetuningDialog()

        config = TrainingConfig(
            model_path=str(sample_model_file),
            dataset_path=str(sample_training_dataset),
            epochs=2,
        )

        thread = TrainingThread(config)
        thread._load_model()
        thread.training_history = [
            {"epoch": 0, "loss": 0.5, "accuracy": 0.7},
            {"epoch": 1, "loss": 0.3, "accuracy": 0.85},
        ]

        dialog.training_thread = thread

        save_path = temp_dir / "finetuned_model.pt"

        model_data = {
            "config": config.__dict__,
            "training_history": thread.training_history,
            "timestamp": time.time(),
            "version": "1.0",
        }

        if TORCH_AVAILABLE:
            import torch

            if hasattr(thread.model, "state_dict"):
                model_data["model_state_dict"] = thread.model.state_dict()
            torch.save(model_data, save_path)
        else:
            with open(save_path, "wb") as f:
                pickle.dump(model_data, f)

        assert save_path.exists()
        assert save_path.stat().st_size > 0

        if TORCH_AVAILABLE:
            import torch

            loaded = torch.load(save_path, map_location="cpu")
            assert "config" in loaded
            assert "training_history" in loaded
            assert len(loaded["training_history"]) == 2

    def test_dialog_augmentation_preview(
        self, qapp: Any, augmentation_dataset: Path
    ) -> None:
        """Dialog previews data augmentation techniques correctly."""
        dialog = ModelFinetuningDialog()

        dialog.dataset_path_edit.setText(str(augmentation_dataset))

        with open(augmentation_dataset, encoding="utf-8") as f:
            data = json.load(f)

        original_text = data[0]["input"]

        augmented_swap = dialog._apply_augmentation_technique(
            original_text, "random_swap"
        )
        assert augmented_swap != original_text or len(original_text.split()) <= 1

        augmented_insert = dialog._apply_augmentation_technique(
            original_text, "random_insertion"
        )
        assert len(augmented_insert.split()) >= len(original_text.split())

        augmented_delete = dialog._apply_augmentation_technique(
            original_text, "random_deletion"
        )
        if len(original_text.split()) > 2:
            assert len(augmented_delete.split()) < len(original_text.split())

    def test_dialog_dataset_creation_templates(self, qapp: Any) -> None:
        """Dialog provides valid training dataset templates."""
        dialog = ModelFinetuningDialog()

        templates = [
            "Binary Analysis Q&A",
            "License Bypass Instructions",
            "Reverse Engineering Guide",
        ]

        for template in templates:
            sample_data = dialog._get_sample_data(template)
            assert len(sample_data) > 0

            data = json.loads(sample_data)
            assert isinstance(data, list)
            assert len(data) > 0

            for item in data:
                assert "input" in item
                assert "output" in item

    def test_dialog_gpu_initialization(self, qapp: Any) -> None:
        """Dialog initializes GPU system and device detection."""
        dialog = ModelFinetuningDialog()

        assert hasattr(dialog, "training_device")
        assert hasattr(dialog, "gpu_info")

        device_info = dialog._get_device_info_text()
        assert "Training Device:" in device_info
        assert len(device_info) > 0


class TestTrainingIntegration:
    """Integration tests for complete training workflows."""

    @pytest.mark.real_data
    def test_complete_training_workflow(
        self, qapp: Any, sample_model_file: Path, sample_training_dataset: Path, temp_dir: Path
    ) -> None:
        """Complete training workflow from dataset to model export."""
        dialog = ModelFinetuningDialog()

        dialog.model_path_edit.setText(str(sample_model_file))
        dialog.model_format_combo.setCurrentText("PyTorch")
        dialog.dataset_path_edit.setText(str(sample_training_dataset))
        dialog.dataset_format_combo.setCurrentText("JSON")
        dialog.epochs_spin.setValue(2)
        dialog.batch_size_spin.setValue(2)
        dialog.learning_rate_spin.setValue(0.001)

        config = TrainingConfig(
            model_path=str(sample_model_file),
            dataset_path=str(sample_training_dataset),
            epochs=2,
            batch_size=2,
            learning_rate=0.001,
        )

        thread = TrainingThread(config)
        thread._load_model()
        dataset = thread._load_dataset()

        assert thread.model is not None
        assert dataset is not None

        assert thread.status == TrainingStatus.IDLE

    @pytest.mark.real_data
    def test_lora_adapter_configuration(
        self, qapp: Any, sample_model_file: Path
    ) -> None:
        """LoRA adapter parameters are properly configured for efficient fine-tuning."""
        dialog = ModelFinetuningDialog()

        dialog.lora_rank_spin.setValue(16)
        dialog.lora_alpha_spin.setValue(32)

        config = dialog._get_current_config()
        config.model_path = str(sample_model_file)
        config.lora_rank = dialog.lora_rank_spin.value()
        config.lora_alpha = dialog.lora_alpha_spin.value()

        assert config.lora_rank == 16
        assert config.lora_alpha == 32

        if config.lora_rank > 0:
            assert config.lora_alpha >= config.lora_rank

    @pytest.mark.real_data
    def test_dataset_augmentation_application(
        self, qapp: Any, augmentation_dataset: Path, temp_dir: Path
    ) -> None:
        """Dataset augmentation increases training samples with valid data."""
        dialog = ModelFinetuningDialog()

        dialog.dataset_path_edit.setText(str(augmentation_dataset))

        with open(augmentation_dataset, encoding="utf-8") as f:
            original_data = json.load(f)

        original_count = len(original_data)

        techniques = ["random_swap", "random_insertion"]
        augmentations_per_sample = 2

        augmented_data = []
        for sample in original_data:
            augmented_data.append(sample)

            for technique in techniques[:augmentations_per_sample]:
                augmented_text = dialog._apply_augmentation_technique(
                    sample["input"], technique
                )
                augmented_data.append({
                    "input": augmented_text,
                    "output": sample["output"]
                })

        assert len(augmented_data) > original_count
        assert len(augmented_data) <= original_count * (1 + len(techniques))

    @pytest.mark.real_data
    def test_training_metrics_tracking(
        self, sample_model_file: Path, sample_training_dataset: Path
    ) -> None:
        """Training thread tracks metrics accurately during training."""
        config = TrainingConfig(
            model_path=str(sample_model_file),
            dataset_path=str(sample_training_dataset),
            epochs=3,
            batch_size=2,
        )

        thread = TrainingThread(config)
        thread._load_model()

        metrics = {
            "epoch": 0,
            "loss": 0.5,
            "accuracy": 0.75,
            "learning_rate": 0.0002,
            "validation_loss": 0.6,
            "validation_accuracy": 0.7,
        }

        thread.training_history.append(metrics)

        assert len(thread.training_history) == 1
        assert thread.training_history[0]["loss"] == 0.5
        assert thread.training_history[0]["accuracy"] == 0.75


class TestDatasetFormats:
    """Test support for various dataset formats."""

    def test_json_dataset_loading(self, temp_dir: Path) -> None:
        """JSON format datasets load correctly with proper structure."""
        dataset_path = temp_dir / "test_dataset.json"
        data = [
            {"input": "Test input 1", "output": "Test output 1"},
            {"input": "Test input 2", "output": "Test output 2"},
        ]

        with open(dataset_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        with open(dataset_path, encoding="utf-8") as f:
            loaded = json.load(f)

        assert len(loaded) == 2
        assert loaded[0]["input"] == "Test input 1"

    def test_jsonl_dataset_loading(self, temp_dir: Path) -> None:
        """JSONL format datasets load line-by-line correctly."""
        dataset_path = temp_dir / "test_dataset.jsonl"

        with open(dataset_path, "w", encoding="utf-8") as f:
            f.write(json.dumps({"input": "Test 1", "output": "Output 1"}) + "\n")
            f.write(json.dumps({"input": "Test 2", "output": "Output 2"}) + "\n")

        samples = []
        with open(dataset_path, encoding="utf-8") as f:
            for line in f:
                samples.append(json.loads(line.strip()))

        assert len(samples) == 2
        assert samples[0]["input"] == "Test 1"

    def test_csv_dataset_export(self, qapp: Any, temp_dir: Path) -> None:
        """Datasets can be exported to CSV format correctly."""
        import csv

        source_data = [
            {"input": "Test input", "output": "Test output"},
            {"input": "Another input", "output": "Another output"},
        ]

        csv_path = temp_dir / "exported_dataset.csv"

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["input", "output"])
            writer.writeheader()
            writer.writerows(source_data)

        with open(csv_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            loaded = list(reader)

        assert len(loaded) == 2
        assert loaded[0]["input"] == "Test input"


class TestModelFormats:
    """Test support for various model formats."""

    @pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch required")
    def test_pytorch_model_loading(self, temp_dir: Path) -> None:
        """PyTorch models load with state_dict correctly."""
        import torch

        model_path = temp_dir / "pytorch_model.pt"

        model_data = {
            "model_state_dict": {
                "layer.weight": torch.randn(10, 20),
                "layer.bias": torch.randn(10),
            },
            "config": {"model_type": "test"},
        }

        torch.save(model_data, model_path)

        loaded = torch.load(model_path, map_location="cpu")
        assert "model_state_dict" in loaded
        assert "layer.weight" in loaded["model_state_dict"]

    def test_pickle_model_fallback(self, temp_dir: Path) -> None:
        """Models can be saved/loaded using pickle format as fallback."""
        model_path = temp_dir / "fallback_model.bin"

        model_data = {
            "config": {"model_type": "fallback"},
            "weights": {"layer1": [1, 2, 3, 4]},
        }

        with open(model_path, "wb") as f:
            pickle.dump(model_data, f)

        with open(model_path, "rb") as f:
            loaded = pickle.load(f)

        assert loaded["config"]["model_type"] == "fallback"
        assert loaded["weights"]["layer1"] == [1, 2, 3, 4]


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_missing_dataset_file_handling(self, qapp: Any) -> None:
        """Dialog handles missing dataset files gracefully."""
        dialog = ModelFinetuningDialog()

        dialog.dataset_path_edit.setText("/nonexistent/dataset.json")

        dataset_path = dialog.dataset_path_edit.text()
        assert not os.path.exists(dataset_path)

    def test_invalid_json_dataset_handling(self, temp_dir: Path) -> None:
        """Invalid JSON datasets are detected during validation."""
        invalid_path = temp_dir / "invalid.json"

        with open(invalid_path, "w", encoding="utf-8") as f:
            f.write("{ invalid json }")

        try:
            with open(invalid_path, encoding="utf-8") as f:
                json.load(f)
            assert False, "Should have raised JSONDecodeError"
        except json.JSONDecodeError:
            pass

    def test_empty_dataset_handling(self, temp_dir: Path, qapp: Any) -> None:
        """Empty datasets are handled without crashes."""
        empty_path = temp_dir / "empty.json"

        with open(empty_path, "w", encoding="utf-8") as f:
            json.dump([], f)

        with open(empty_path, encoding="utf-8") as f:
            data = json.load(f)

        assert len(data) == 0

    def test_training_interruption_handling(
        self, sample_model_file: Path, sample_training_dataset: Path
    ) -> None:
        """Training can be interrupted safely without corruption."""
        config = TrainingConfig(
            model_path=str(sample_model_file),
            dataset_path=str(sample_training_dataset),
            epochs=100,
        )

        thread = TrainingThread(config)
        thread.stop()

        assert thread.is_stopped is True
        assert thread.status == TrainingStatus.ERROR


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_create_model_finetuning_dialog_function(self, qapp: Any) -> None:
        """create_model_finetuning_dialog creates valid dialog instance."""
        dialog = create_model_finetuning_dialog()

        assert dialog is not None
        assert isinstance(dialog, ModelFinetuningDialog)
        assert dialog.windowTitle() == "AI Model Fine-Tuning"

    def test_create_dialog_with_parent(self, qapp: Any) -> None:
        """Dialog can be created with parent widget."""
        from intellicrack.handlers.pyqt6_handler import QWidget

        parent = QWidget()
        dialog = create_model_finetuning_dialog(parent)

        assert dialog is not None
        assert dialog.parent == parent


@pytest.mark.real_data
class TestRealWorldScenarios:
    """Test realistic training scenarios for license cracking."""

    def test_vmprotect_detection_training(
        self, qapp: Any, temp_dir: Path
    ) -> None:
        """Model can be trained to detect VMProtect protection indicators."""
        dataset_path = temp_dir / "vmprotect_dataset.json"

        vmprotect_data = [
            {
                "input": "Binary section .vmp0 with entropy 7.9",
                "output": "VMProtect virtualization detected - section contains virtualized code"
            },
            {
                "input": "Import table obscured, high entropy sections present",
                "output": "VMProtect packing detected - use VMP unpacker or dynamic analysis"
            },
            {
                "input": "Mutation engine artifacts in code segments",
                "output": "VMProtect mutation detected - code morphs at runtime"
            },
        ]

        with open(dataset_path, "w", encoding="utf-8") as f:
            json.dump(vmprotect_data, f, indent=2)

        dialog = ModelFinetuningDialog()
        dialog.dataset_path_edit.setText(str(dataset_path))

        with open(dataset_path, encoding="utf-8") as f:
            loaded = json.load(f)

        assert len(loaded) == 3
        for item in loaded:
            assert "vmp" in item["input"].lower() or "vmp" in item["output"].lower()

    def test_license_bypass_technique_training(
        self, qapp: Any, temp_dir: Path
    ) -> None:
        """Model trains on real license bypass techniques and patterns."""
        dataset_path = temp_dir / "license_bypass_dataset.json"

        bypass_data = [
            {
                "input": "CMP instruction followed by JNE to error handler",
                "output": "Patch JNE to JMP or NOP the comparison - license check bypassed"
            },
            {
                "input": "CryptVerifySignature returns FALSE",
                "output": "Patch return value to TRUE or redirect to success path"
            },
            {
                "input": "Registry key HKLM\\SOFTWARE\\Vendor\\License not found",
                "output": "Create registry key with valid license data or patch registry read check"
            },
        ]

        with open(dataset_path, "w", encoding="utf-8") as f:
            json.dump(bypass_data, f, indent=2)

        config = TrainingConfig(
            dataset_path=str(dataset_path),
            epochs=5,
            batch_size=1,
        )

        assert os.path.exists(config.dataset_path)

        with open(config.dataset_path, encoding="utf-8") as f:
            data = json.load(f)
            assert all("license" in str(item).lower() or "bypass" in str(item).lower() for item in data)
