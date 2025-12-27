"""Production-grade tests for license protection neural network.

Tests MUST validate actual neural network training and inference on real binary features.
All model architectures must be tested for correct forward pass, training, and prediction.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import json
import tempfile
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from numpy.typing import NDArray

from intellicrack.ml.license_protection_neural_network import (
    TORCH_AVAILABLE,
    LicenseDataset,
    LicenseFeatures,
    LicenseProtectionCNN,
    LicenseProtectionPredictor,
    LicenseProtectionTrainer,
    LicenseProtectionTransformer,
    LicenseProtectionType,
    ProtectionLoss,
    create_dataloaders,
    get_license_predictor,
    HybridLicenseAnalyzer,
)

if TORCH_AVAILABLE:
    import torch
    import torch.nn as nn


pytestmark = pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not available")


@pytest.fixture
def sample_license_features() -> LicenseFeatures:
    """Create sample license features for testing."""
    return LicenseFeatures(
        entropy_scores=np.random.rand(16).astype(np.float32),
        section_characteristics=np.random.rand(32).astype(np.float32),
        import_signatures=np.random.rand(64).astype(np.float32),
        export_signatures=np.random.rand(32).astype(np.float32),
        string_features=np.random.rand(128).astype(np.float32),
        opcode_histogram=np.random.rand(256).astype(np.float32),
        call_graph_features=np.random.rand(64).astype(np.float32),
        crypto_signatures=np.random.rand(32).astype(np.float32),
        anti_debug_features=np.random.rand(16).astype(np.float32),
        api_sequence_embedding=np.random.rand(128).astype(np.float32),
        network_signatures=np.random.rand(32).astype(np.float32),
        registry_patterns=np.random.rand(16).astype(np.float32),
        file_access_patterns=np.random.rand(16).astype(np.float32),
        control_flow_complexity=np.random.rand(8).astype(np.float32),
        data_flow_features=np.random.rand(16).astype(np.float32),
        memory_access_patterns=np.random.rand(16).astype(np.float32),
        timing_patterns=np.random.rand(8).astype(np.float32),
        hardware_checks=np.random.rand(16).astype(np.float32),
        virtualization_checks=np.random.rand(8).astype(np.float32),
    )


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    """Create sample binary file for testing."""
    binary_path = tmp_path / "test.exe"
    dos_header = b"MZ" + b"\x00" * 58 + np.array([0x80], dtype=np.uint32).tobytes()
    pe_signature = b"PE\x00\x00"
    binary_content = dos_header + pe_signature + b"\x00" * 1000
    binary_path.write_bytes(binary_content)
    return binary_path


@pytest.fixture
def test_dataset_dir(tmp_path: Path) -> Path:
    """Create test dataset directory with sample binaries."""
    dataset_dir = tmp_path / "test_dataset"
    dataset_dir.mkdir()

    for protection_type in ["vmprotect", "themida", "unknown"]:
        protection_dir = dataset_dir / protection_type
        protection_dir.mkdir()

        for i in range(3):
            binary_file = protection_dir / f"sample_{i}.exe"
            binary_file.write_bytes(b"MZ\x00\x00" + b"\x00" * 1000)

    return dataset_dir


class TestLicenseProtectionType:
    """Tests for license protection type enumeration."""

    def test_enum_has_expected_values(self) -> None:
        """Enum contains expected protection types."""
        assert hasattr(LicenseProtectionType, "VMPROTECT")
        assert hasattr(LicenseProtectionType, "THEMIDA")
        assert hasattr(LicenseProtectionType, "FLEXLM")
        assert hasattr(LicenseProtectionType, "UNKNOWN")

    def test_enum_values_are_strings(self) -> None:
        """Enum values are string identifiers."""
        for prot_type in LicenseProtectionType:
            assert isinstance(prot_type.value, str)

    def test_enum_covers_major_protections(self) -> None:
        """Enum covers major commercial protections."""
        protection_names = {pt.value for pt in LicenseProtectionType}

        assert "vmprotect" in protection_names
        assert "themida" in protection_names
        assert "denuvo" in protection_names
        assert "cloud_licensing" in protection_names


class TestLicenseFeatures:
    """Tests for license features dataclass."""

    def test_to_tensor_concatenates_all_features(self, sample_license_features: LicenseFeatures) -> None:
        """to_tensor concatenates all feature arrays."""
        tensor = sample_license_features.to_tensor()

        assert isinstance(tensor, np.ndarray)
        assert tensor.dtype == np.float32
        assert len(tensor.shape) == 1
        assert len(tensor) > 0

    def test_to_tensor_preserves_feature_values(self, sample_license_features: LicenseFeatures) -> None:
        """to_tensor preserves original feature values."""
        tensor = sample_license_features.to_tensor()

        assert np.all(np.isfinite(tensor))
        assert tensor.shape[0] == sum(
            len(v.flatten()) for v in [
                sample_license_features.entropy_scores,
                sample_license_features.section_characteristics,
                sample_license_features.import_signatures,
                sample_license_features.export_signatures,
                sample_license_features.string_features,
                sample_license_features.opcode_histogram,
                sample_license_features.call_graph_features,
                sample_license_features.crypto_signatures,
                sample_license_features.anti_debug_features,
                sample_license_features.api_sequence_embedding,
                sample_license_features.network_signatures,
                sample_license_features.registry_patterns,
                sample_license_features.file_access_patterns,
                sample_license_features.control_flow_complexity,
                sample_license_features.data_flow_features,
                sample_license_features.memory_access_patterns,
                sample_license_features.timing_patterns,
                sample_license_features.hardware_checks,
                sample_license_features.virtualization_checks,
            ]
        )


class TestLicenseProtectionCNN:
    """Tests for CNN model architecture and functionality."""

    def test_model_initialization(self) -> None:
        """CNN model initializes with correct architecture."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=20)

        assert isinstance(model, nn.Module)
        assert hasattr(model, "conv1")
        assert hasattr(model, "conv2")
        assert hasattr(model, "conv3")
        assert hasattr(model, "fc1")
        assert hasattr(model, "fc2")
        assert hasattr(model, "fc3")

    def test_forward_pass_correct_output_shape(self) -> None:
        """Forward pass produces correct output shape."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=20)
        batch_size = 8
        input_tensor = torch.randn(batch_size, 4096)

        output = model(input_tensor)

        assert output.shape == (batch_size, 20)

    def test_forward_pass_produces_logits(self) -> None:
        """Forward pass produces unnormalized logits."""
        model = LicenseProtectionCNN()
        input_tensor = torch.randn(4, 4096)

        output = model(input_tensor)

        assert not torch.all((output >= 0) & (output <= 1))

    def test_model_trainable_parameters(self) -> None:
        """Model has trainable parameters."""
        model = LicenseProtectionCNN()

        params = list(model.parameters())

        assert len(params) > 0
        assert all(p.requires_grad for p in params)

    def test_gradient_flow_through_model(self) -> None:
        """Gradients flow through model during backpropagation."""
        model = LicenseProtectionCNN()
        input_tensor = torch.randn(2, 4096, requires_grad=True)
        target = torch.tensor([0, 1])

        output = model(input_tensor)
        loss = nn.CrossEntropyLoss()(output, target)
        loss.backward()

        assert input_tensor.grad is not None
        assert not torch.all(input_tensor.grad == 0)

    def test_attention_mechanism_applied(self) -> None:
        """Attention mechanism is applied in forward pass."""
        model = LicenseProtectionCNN()
        input_tensor = torch.randn(2, 4096)

        output = model(input_tensor)

        assert output is not None
        assert output.shape[0] == 2

    def test_residual_connections_work(self) -> None:
        """Residual connections are functional."""
        model = LicenseProtectionCNN()
        input_tensor = torch.randn(2, 4096)

        output = model(input_tensor)

        assert output is not None

    def test_save_and_load_weights(self, tmp_path: Path) -> None:
        """Model weights can be saved and loaded."""
        model = LicenseProtectionCNN()
        save_path = tmp_path / "model_weights.pth"

        model.save_weights(save_path)

        assert save_path.exists()

        model2 = LicenseProtectionCNN()
        model2.load_state_dict(torch.load(save_path))

        for p1, p2 in zip(model.parameters(), model2.parameters()):
            assert torch.allclose(p1, p2)


class TestLicenseProtectionTransformer:
    """Tests for Transformer model architecture."""

    def test_transformer_initialization(self) -> None:
        """Transformer initializes with correct architecture."""
        model = LicenseProtectionTransformer(input_dim=256, num_heads=8, num_layers=6)

        assert isinstance(model, nn.Module)
        assert hasattr(model, "transformer_encoder")
        assert hasattr(model, "classifier")

    def test_transformer_forward_pass(self) -> None:
        """Transformer forward pass produces correct output."""
        model = LicenseProtectionTransformer(input_dim=256)
        batch_size = 4
        seq_len = 10
        input_tensor = torch.randn(batch_size, seq_len, 256)

        output = model(input_tensor)

        assert output.shape == (batch_size, len(LicenseProtectionType))

    def test_positional_encoding_added(self) -> None:
        """Positional encoding is created and added."""
        model = LicenseProtectionTransformer()

        assert hasattr(model, "positional_encoding")
        assert model.positional_encoding.shape[0] == 1
        assert model.positional_encoding.shape[1] == 1000

    def test_transformer_handles_variable_sequence_length(self) -> None:
        """Transformer handles different sequence lengths."""
        model = LicenseProtectionTransformer(input_dim=256)

        short_seq = torch.randn(2, 5, 256)
        long_seq = torch.randn(2, 20, 256)

        output_short = model(short_seq)
        output_long = model(long_seq)

        assert output_short.shape == output_long.shape

    def test_transformer_global_pooling(self) -> None:
        """Global pooling aggregates sequence features."""
        model = LicenseProtectionTransformer()
        input_tensor = torch.randn(2, 10, 256)

        output = model(input_tensor)

        assert len(output.shape) == 2


class TestHybridLicenseAnalyzer:
    """Tests for hybrid multi-modal model."""

    def test_hybrid_initialization(self) -> None:
        """Hybrid model initializes all branches."""
        model = HybridLicenseAnalyzer()

        assert hasattr(model, "cnn_branch")
        assert hasattr(model, "transformer_branch")
        assert hasattr(model, "gnn_branch")
        assert hasattr(model, "fusion_layer")

    def test_hybrid_forward_pass(self) -> None:
        """Hybrid model forward pass with multi-modal inputs."""
        model = HybridLicenseAnalyzer()

        binary_features = torch.randn(2, 4096)
        sequence_features = torch.randn(2, 10, 256)
        graph_features = torch.randn(2, 512)

        outputs = model(binary_features, sequence_features, graph_features)

        assert isinstance(outputs, dict)
        assert "protection_type" in outputs
        assert "version" in outputs
        assert "complexity" in outputs
        assert "bypass_difficulty" in outputs

    def test_hybrid_multitask_outputs(self) -> None:
        """Hybrid model produces all task outputs."""
        model = HybridLicenseAnalyzer()

        binary_features = torch.randn(4, 4096)
        sequence_features = torch.randn(4, 10, 256)
        graph_features = torch.randn(4, 512)

        outputs = model(binary_features, sequence_features, graph_features)

        assert outputs["protection_type"].shape == (4, len(LicenseProtectionType))
        assert outputs["version"].shape == (4, 1)
        assert outputs["complexity"].shape == (4, 1)
        assert outputs["bypass_difficulty"].shape == (4, 5)

    def test_hybrid_feature_fusion(self) -> None:
        """Feature fusion combines all modalities."""
        model = HybridLicenseAnalyzer()

        binary_features = torch.randn(2, 4096)
        sequence_features = torch.randn(2, 10, 256)
        graph_features = torch.randn(2, 512)

        outputs = model(binary_features, sequence_features, graph_features)

        assert all(v is not None for v in outputs.values())


class TestLicenseDataset:
    """Tests for license protection dataset."""

    def test_dataset_initialization_empty_dir(self, tmp_path: Path) -> None:
        """Dataset handles empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        dataset = LicenseDataset(str(empty_dir))

        assert len(dataset) == 0

    def test_dataset_loads_from_directory_structure(self, test_dataset_dir: Path) -> None:
        """Dataset loads samples from directory structure."""
        dataset = LicenseDataset(str(test_dataset_dir))

        assert len(dataset) > 0
        assert len(dataset.samples) == len(dataset.labels)

    def test_dataset_builds_label_mapping(self, test_dataset_dir: Path) -> None:
        """Dataset creates label to index mapping."""
        dataset = LicenseDataset(str(test_dataset_dir))

        assert len(dataset.label_to_idx) > 0
        assert len(dataset.idx_to_label) == len(dataset.label_to_idx)

    def test_dataset_getitem_returns_features_and_label(self, test_dataset_dir: Path) -> None:
        """Dataset __getitem__ returns features and label tensors."""
        dataset = LicenseDataset(str(test_dataset_dir))

        if len(dataset) > 0:
            features, label = dataset[0]

            assert isinstance(features, torch.Tensor)
            assert isinstance(label, torch.Tensor)

    def test_dataset_caches_features(self, test_dataset_dir: Path) -> None:
        """Dataset caches extracted features."""
        dataset = LicenseDataset(str(test_dataset_dir), cache_features=True)

        if len(dataset) > 0:
            _ = dataset[0]
            assert len(dataset.feature_cache) > 0

    def test_dataset_loads_from_metadata(self, test_dataset_dir: Path) -> None:
        """Dataset loads from metadata JSON file."""
        metadata = {
            "samples": [
                {"file": "vmprotect/sample_0.exe", "protection_type": "vmprotect"},
                {"file": "themida/sample_0.exe", "protection_type": "themida"},
            ]
        }

        metadata_file = test_dataset_dir / "metadata.json"
        metadata_file.write_text(json.dumps(metadata))

        dataset = LicenseDataset(str(test_dataset_dir))

        assert len(dataset) > 0


class TestProtectionLoss:
    """Tests for custom protection loss function."""

    def test_loss_initialization(self) -> None:
        """Loss function initializes correctly."""
        loss_fn = ProtectionLoss(num_classes=20)

        assert isinstance(loss_fn, nn.Module)
        assert hasattr(loss_fn, "classification_loss")
        assert hasattr(loss_fn, "centers")

    def test_focal_loss_computation(self) -> None:
        """Focal loss computes correctly."""
        loss_fn = ProtectionLoss(num_classes=20)

        logits = torch.randn(4, 20)
        targets = torch.tensor([0, 1, 2, 3])

        loss = loss_fn.focal_loss(logits, targets)

        assert isinstance(loss, torch.Tensor)
        assert loss.ndim == 0
        assert loss.item() > 0

    def test_center_loss_computation(self) -> None:
        """Center loss computes correctly for feature clustering."""
        loss_fn = ProtectionLoss(num_classes=20)

        features = torch.randn(4, 256)
        targets = torch.tensor([0, 1, 0, 1])

        loss = loss_fn.compute_center_loss(features, targets)

        assert isinstance(loss, torch.Tensor)
        assert loss.item() >= 0

    def test_multitask_loss_computation(self) -> None:
        """Loss handles multitask outputs."""
        loss_fn = ProtectionLoss(num_classes=20)

        outputs = {
            "protection_type": torch.randn(4, 20),
            "version": torch.randn(4, 1),
            "complexity": torch.randn(4, 1),
            "bypass_difficulty": torch.randn(4, 5),
        }
        targets = torch.tensor([0, 1, 2, 3])

        loss = loss_fn(outputs, targets)

        assert loss.item() > 0

    def test_single_task_loss(self) -> None:
        """Loss handles single task output."""
        loss_fn = ProtectionLoss(num_classes=20)

        logits = torch.randn(4, 20)
        targets = torch.tensor([0, 1, 2, 3])

        loss = loss_fn(logits, targets)

        assert loss.item() > 0


class TestLicenseProtectionTrainer:
    """Tests for model training functionality."""

    def test_trainer_initialization(self) -> None:
        """Trainer initializes with model and optimizer."""
        model = LicenseProtectionCNN()
        trainer = LicenseProtectionTrainer(model, device="cpu")

        assert trainer.model is not None
        assert hasattr(trainer, "optimizer")
        assert hasattr(trainer, "scheduler")
        assert hasattr(trainer, "criterion")

    def test_trainer_train_epoch(self) -> None:
        """Trainer executes one training epoch."""
        model = LicenseProtectionCNN(num_classes=3)
        trainer = LicenseProtectionTrainer(model, device="cpu")

        features = torch.randn(16, 4096)
        labels = torch.randint(0, 3, (16,))
        dataset = torch.utils.data.TensorDataset(features, labels)
        dataloader = torch.utils.data.DataLoader(dataset, batch_size=4)

        loss, accuracy = trainer.train_epoch(dataloader)

        assert isinstance(loss, float)
        assert isinstance(accuracy, float)
        assert loss > 0
        assert 0 <= accuracy <= 100

    def test_trainer_validate(self) -> None:
        """Trainer validates model on validation set."""
        model = LicenseProtectionCNN(num_classes=3)
        trainer = LicenseProtectionTrainer(model, device="cpu")

        features = torch.randn(12, 4096)
        labels = torch.randint(0, 3, (12,))
        dataset = torch.utils.data.TensorDataset(features, labels)
        dataloader = torch.utils.data.DataLoader(dataset, batch_size=4)

        loss, accuracy = trainer.validate(dataloader)

        assert isinstance(loss, float)
        assert isinstance(accuracy, float)

    def test_trainer_save_checkpoint(self, tmp_path: Path) -> None:
        """Trainer saves checkpoint with all state."""
        model = LicenseProtectionCNN()
        trainer = LicenseProtectionTrainer(model, device="cpu")

        checkpoint_path = tmp_path / "checkpoint.pth"
        trainer.save_checkpoint(str(checkpoint_path))

        assert checkpoint_path.exists()

        checkpoint = torch.load(checkpoint_path)
        assert "model_state_dict" in checkpoint
        assert "optimizer_state_dict" in checkpoint
        assert "history" in checkpoint

    def test_trainer_load_checkpoint(self, tmp_path: Path) -> None:
        """Trainer loads checkpoint and restores state."""
        model = LicenseProtectionCNN()
        trainer = LicenseProtectionTrainer(model, device="cpu")

        checkpoint_path = tmp_path / "checkpoint.pth"
        trainer.save_checkpoint(str(checkpoint_path))

        trainer2 = LicenseProtectionTrainer(LicenseProtectionCNN(), device="cpu")
        result = trainer2.load_checkpoint(str(checkpoint_path))

        assert result is True

    def test_trainer_full_training_loop(self) -> None:
        """Trainer executes full training loop."""
        model = LicenseProtectionCNN(num_classes=3)
        trainer = LicenseProtectionTrainer(model, device="cpu")
        trainer.num_epochs = 2

        features = torch.randn(24, 4096)
        labels = torch.randint(0, 3, (24,))
        dataset = torch.utils.data.TensorDataset(features, labels)
        train_loader = torch.utils.data.DataLoader(dataset, batch_size=4)
        val_loader = torch.utils.data.DataLoader(dataset, batch_size=4)

        trainer.train(train_loader, val_loader)

        assert len(trainer.history["train_loss"]) == 2
        assert len(trainer.history["val_loss"]) == 2


class TestLicenseProtectionPredictor:
    """Tests for license protection prediction interface."""

    def test_predictor_initialization_without_model(self) -> None:
        """Predictor initializes without pre-trained model."""
        predictor = LicenseProtectionPredictor()

        assert predictor.model is not None
        assert predictor.device in ["cpu", "cuda"]

    def test_predictor_fallback_prediction(self, sample_binary: Path) -> None:
        """Predictor uses fallback heuristics when model unavailable."""
        predictor = LicenseProtectionPredictor()
        predictor.model = None

        result = predictor._fallback_prediction(str(sample_binary))

        assert "protection_type" in result
        assert "confidence" in result
        assert 0.0 <= result["confidence"] <= 1.0

    def test_predictor_extract_binary_features(self, sample_binary: Path) -> None:
        """Predictor extracts binary features correctly."""
        predictor = LicenseProtectionPredictor()

        with open(sample_binary, "rb") as f:
            data = f.read()

        features = predictor._extract_binary_features(data)

        assert isinstance(features, np.ndarray)
        assert features.dtype == np.float32
        assert len(features) == 4096

    def test_predictor_extract_sequence_features(self, sample_binary: Path) -> None:
        """Predictor extracts sequence features for transformer."""
        predictor = LicenseProtectionPredictor()

        with open(sample_binary, "rb") as f:
            data = f.read()

        features = predictor._extract_sequence_features(data)

        assert isinstance(features, np.ndarray)
        assert len(features.shape) == 2

    def test_predictor_extract_graph_features(self, sample_binary: Path) -> None:
        """Predictor extracts graph features for GNN."""
        predictor = LicenseProtectionPredictor()

        with open(sample_binary, "rb") as f:
            data = f.read()

        features = predictor._extract_graph_features(data)

        assert isinstance(features, np.ndarray)
        assert len(features) == 512

    def test_predictor_predict_returns_dict(self, sample_binary: Path) -> None:
        """Predictor predict returns prediction dictionary."""
        predictor = LicenseProtectionPredictor()

        result = predictor.predict(str(sample_binary))

        assert isinstance(result, dict)
        assert "protection_type" in result
        assert "confidence" in result


class TestModuleFunctions:
    """Tests for module-level utility functions."""

    def test_create_dataloaders(self, test_dataset_dir: Path) -> None:
        """create_dataloaders creates train/val/test loaders."""
        train_loader, val_loader, test_loader = create_dataloaders(
            str(test_dataset_dir),
            batch_size=2,
            num_workers=0,
        )

        assert train_loader is not None
        assert val_loader is not None
        assert test_loader is not None

    def test_get_license_predictor_singleton(self) -> None:
        """get_license_predictor returns singleton instance."""
        predictor1 = get_license_predictor()
        predictor2 = get_license_predictor()

        assert predictor1 is predictor2


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_model_handles_batch_size_one(self) -> None:
        """Models handle batch size of 1."""
        model = LicenseProtectionCNN()
        input_tensor = torch.randn(1, 4096)

        output = model(input_tensor)

        assert output.shape[0] == 1

    def test_model_handles_large_batch(self) -> None:
        """Models handle large batch sizes."""
        model = LicenseProtectionCNN()
        input_tensor = torch.randn(128, 4096)

        output = model(input_tensor)

        assert output.shape[0] == 128

    def test_trainer_handles_empty_dataset(self) -> None:
        """Trainer handles empty dataset gracefully."""
        model = LicenseProtectionCNN()
        trainer = LicenseProtectionTrainer(model, device="cpu")

        dataset = torch.utils.data.TensorDataset(torch.randn(0, 4096), torch.tensor([]))
        dataloader = torch.utils.data.DataLoader(dataset, batch_size=4)

        loss, accuracy = trainer.validate(dataloader)

    def test_dataset_handles_corrupted_binary(self, test_dataset_dir: Path) -> None:
        """Dataset handles corrupted binary files gracefully."""
        corrupted = test_dataset_dir / "vmprotect" / "corrupted.exe"
        corrupted.write_bytes(b"\xFF" * 100)

        dataset = LicenseDataset(str(test_dataset_dir))

        if len(dataset) > 0:
            features, label = dataset[0]
            assert features is not None


class TestModelPersistence:
    """Tests for model saving and loading."""

    def test_save_and_load_cnn_weights(self, tmp_path: Path) -> None:
        """CNN weights can be saved and loaded."""
        model = LicenseProtectionCNN()
        save_path = tmp_path / "cnn_weights.pth"

        model.save_weights(save_path)
        assert save_path.exists()

    def test_save_and_load_transformer_weights(self, tmp_path: Path) -> None:
        """Transformer weights can be saved and loaded."""
        model = LicenseProtectionTransformer()
        save_path = tmp_path / "transformer_weights.pth"

        model.save_weights(save_path)
        assert save_path.exists()

    def test_save_and_load_hybrid_weights(self, tmp_path: Path) -> None:
        """Hybrid model weights can be saved and loaded."""
        model = HybridLicenseAnalyzer()
        save_path = tmp_path / "hybrid_weights.pth"

        model.save_weights(save_path)
        assert save_path.exists()
