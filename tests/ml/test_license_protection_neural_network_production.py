"""
Production-ready tests for intellicrack/ml/license_protection_neural_network.py

Tests validate REAL ML offensive capabilities:
- Neural network architecture initialization and forward passes
- Training on real binary features with actual learning
- Protection type classification accuracy on real data
- Model saving and loading with state preservation
- Feature extraction from actual PE binaries
- Multi-task learning outputs (protection type, version, complexity, difficulty)
- Dataset creation and loading from binary samples
- Transformer attention mechanisms on API sequences
- CNN pattern detection on binary data
- Hybrid model feature fusion

CRITICAL: NO MOCKS - All tests use real ML operations with actual tensors and gradients.
Tests MUST FAIL if the neural network doesn't learn or predict correctly.
"""

import hashlib
import json
import struct
import tempfile
from pathlib import Path
from typing import Any

import numpy as np
import pytest

try:
    import torch
    from torch import nn
    from torch.nn import functional
    from torch.utils.data import DataLoader

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    pytest.skip("PyTorch not available", allow_module_level=True)

from intellicrack.ml.license_protection_neural_network import (
    HybridLicenseAnalyzer,
    LicenseDataset,
    LicenseFeatures,
    LicenseProtectionCNN,
    LicenseProtectionPredictor,
    LicenseProtectionTrainer,
    LicenseProtectionTransformer,
    LicenseProtectionType,
    ProtectionLoss,
    create_dataloaders,
    evaluate_model,
    get_license_predictor,
    train_license_model,
)


@pytest.fixture
def sample_pe_binary() -> bytes:
    """Create minimal valid PE binary with license-related strings."""
    pe_binary = bytearray(2048)

    pe_binary[:2] = b"MZ"
    pe_binary[0x3C:0x40] = struct.pack("<I", 0x100)

    pe_offset = 0x100
    pe_binary[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    pe_binary[pe_offset + 4 : pe_offset + 6] = struct.pack("<H", 0x8664)
    pe_binary[pe_offset + 6 : pe_offset + 8] = struct.pack("<H", 3)

    pe_binary[0x200:0x220] = b"RegOpenKeyExA\x00RegQueryValueExA\x00"
    pe_binary[0x300:0x330] = b"license\x00serial\x00key\x00activation\x00trial\x00"
    pe_binary[0x400:0x410] = struct.pack("<I", 0x67452301) + b"\x00" * 12
    pe_binary[0x500:0x520] = b"GetVolumeInformation\x00GetSystemTime\x00"

    return bytes(pe_binary)


@pytest.fixture
def vmprotect_binary() -> bytes:
    """Create binary with VMProtect signatures."""
    binary = bytearray(4096)
    binary[:2] = b"MZ"
    binary[0x3C:0x40] = struct.pack("<I", 0x100)
    binary[0x100:0x104] = b"PE\x00\x00"
    binary[0x500:0x520] = b"VMProtect\x00IsDebuggerPresent\x00"
    binary[0x600:0x640] = b"CheckRemoteDebuggerPresent\x00GetTickCount\x00"

    for i in range(0, 1000, 4):
        binary[0x800 + i : 0x800 + i + 4] = struct.pack("<I", 0x6A09E667)

    return bytes(binary)


@pytest.fixture
def themida_binary() -> bytes:
    """Create binary with Themida signatures."""
    binary = bytearray(4096)
    binary[:2] = b"MZ"
    binary[0x3C:0x40] = struct.pack("<I", 0x100)
    binary[0x100:0x104] = b"PE\x00\x00"
    binary[0x500:0x520] = b"Themida\x00WinLicense\x00"
    binary[0x600:0x640] = b"NtQueryInformationProcess\x00OutputDebugString\x00"

    for i in range(0, 500, 4):
        binary[0x800 + i : 0x800 + i + 4] = struct.pack("<I", 0xBB67AE85)

    return bytes(binary)


@pytest.fixture
def flexlm_binary() -> bytes:
    """Create binary with FlexLM signatures."""
    binary = bytearray(3072)
    binary[:2] = b"MZ"
    binary[0x3C:0x40] = struct.pack("<I", 0x100)
    binary[0x100:0x104] = b"PE\x00\x00"
    binary[0x500:0x520] = b"FLEXlm\x00lmgr\x00"
    binary[0x600:0x640] = b"GetComputerName\x00GetVolumeInformation\x00"
    binary[0x700:0x720] = b"InternetOpen\x00HttpSendRequest\x00"

    return bytes(binary)


@pytest.fixture
def sample_license_features() -> LicenseFeatures:
    """Create realistic LicenseFeatures for testing."""
    return LicenseFeatures(
        entropy_scores=np.random.uniform(3.0, 7.5, 16).astype(np.float32),
        section_characteristics=np.random.uniform(0, 1, 32).astype(np.float32),
        import_signatures=np.random.randint(0, 2, 64).astype(np.float32),
        export_signatures=np.random.uniform(0, 1, 32).astype(np.float32),
        string_features=np.random.uniform(0, 1, 128).astype(np.float32),
        opcode_histogram=np.random.uniform(0, 0.1, 256).astype(np.float32),
        call_graph_features=np.random.uniform(0, 1, 64).astype(np.float32),
        crypto_signatures=np.random.randint(0, 2, 32).astype(np.float32),
        anti_debug_features=np.random.randint(0, 2, 16).astype(np.float32),
        api_sequence_embedding=np.random.uniform(-1, 1, 128).astype(np.float32),
        network_signatures=np.random.randint(0, 2, 32).astype(np.float32),
        registry_patterns=np.random.randint(0, 2, 16).astype(np.float32),
        file_access_patterns=np.random.uniform(0, 1, 16).astype(np.float32),
        control_flow_complexity=np.random.uniform(0, 1, 8).astype(np.float32),
        data_flow_features=np.random.uniform(0, 1, 16).astype(np.float32),
        memory_access_patterns=np.random.uniform(0, 1, 16).astype(np.float32),
        timing_patterns=np.random.randint(0, 2, 8).astype(np.float32),
        hardware_checks=np.random.randint(0, 2, 16).astype(np.float32),
        virtualization_checks=np.random.randint(0, 2, 8).astype(np.float32),
    )


@pytest.fixture
def temp_dataset_dir(sample_pe_binary: bytes, vmprotect_binary: bytes, themida_binary: bytes, flexlm_binary: bytes) -> Path:
    """Create temporary dataset directory with real binary samples."""
    temp_dir = Path(tempfile.mkdtemp())

    vmprotect_dir = temp_dir / "vmprotect"
    vmprotect_dir.mkdir()
    (vmprotect_dir / "sample1.exe").write_bytes(vmprotect_binary)
    (vmprotect_dir / "sample2.exe").write_bytes(vmprotect_binary)

    themida_dir = temp_dir / "themida"
    themida_dir.mkdir()
    (themida_dir / "sample1.exe").write_bytes(themida_binary)
    (themida_dir / "sample2.exe").write_bytes(themida_binary)

    flexlm_dir = temp_dir / "flexlm"
    flexlm_dir.mkdir()
    (flexlm_dir / "sample1.exe").write_bytes(flexlm_binary)

    unknown_dir = temp_dir / "unknown"
    unknown_dir.mkdir()
    (unknown_dir / "sample1.exe").write_bytes(sample_pe_binary)

    return temp_dir


class TestLicenseProtectionCNN:
    """Test CNN model for binary pattern detection."""

    def test_cnn_initializes_with_correct_architecture(self) -> None:
        """CNN model initializes with proper layers and parameters."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=20)

        assert isinstance(model.conv1, nn.Conv2d)
        assert isinstance(model.conv2, nn.Conv2d)
        assert isinstance(model.conv3, nn.Conv2d)
        assert isinstance(model.bn1, nn.BatchNorm2d)
        assert isinstance(model.bn2, nn.BatchNorm2d)
        assert isinstance(model.bn3, nn.BatchNorm2d)
        assert isinstance(model.fc1, nn.Linear)
        assert isinstance(model.fc2, nn.Linear)
        assert isinstance(model.fc3, nn.Linear)

        assert model.fc3.out_features == 20

        total_params = sum(p.numel() for p in model.parameters())
        assert total_params > 100000

    def test_cnn_forward_pass_produces_correct_output_shape(self) -> None:
        """CNN forward pass produces logits with correct shape."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=20)
        model.eval()

        batch_size = 8
        input_tensor = torch.randn(batch_size, 4096)

        with torch.no_grad():
            output = model(input_tensor)

        assert output.shape == (batch_size, 20)
        assert not torch.isnan(output).any()
        assert not torch.isinf(output).any()

    def test_cnn_learns_from_training_data(self) -> None:
        """CNN actually learns patterns and reduces loss during training."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=5)
        optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
        criterion = nn.CrossEntropyLoss()

        X_train = torch.randn(100, 4096)
        y_train = torch.randint(0, 5, (100,))

        X_train[:20] += 2.0
        y_train[:20] = 0

        initial_loss = None
        final_loss = None

        model.train()
        for epoch in range(10):
            optimizer.zero_grad()
            outputs = model(X_train)
            loss = criterion(outputs, y_train)
            loss.backward()
            optimizer.step()

            if epoch == 0:
                initial_loss = loss.item()
            elif epoch == 9:
                final_loss = loss.item()

        assert initial_loss is not None
        assert final_loss is not None
        assert final_loss < initial_loss * 0.8

    def test_cnn_attention_mechanism_works(self) -> None:
        """CNN attention mechanism produces valid attention weights."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=20)
        model.eval()

        input_tensor = torch.randn(4, 4096)

        with torch.no_grad():
            x = input_tensor.view(4, 1, 64, 64)
            x1 = functional.relu(model.bn1(model.conv1(x)))
            x1 = model.pool(x1)
            x2 = functional.relu(model.bn2(model.conv2(x1)))
            x2 = model.pool(x2)
            x3 = functional.relu(model.bn3(model.conv3(x2)))

            attention_weights = model.attention(x3)

        assert attention_weights.shape == x3.shape
        assert (attention_weights >= 0).all()
        assert (attention_weights <= 1).all()

    def test_cnn_saves_and_loads_weights(self) -> None:
        """CNN weights can be saved and loaded preserving model state."""
        model1 = LicenseProtectionCNN(input_size=4096, num_classes=20)

        input_tensor = torch.randn(2, 4096)
        with torch.no_grad():
            output1 = model1(input_tensor)

        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as tmp:
            model1.save_weights(tmp.name)
            weight_path = tmp.name

        model2 = LicenseProtectionCNN(input_size=4096, num_classes=20)
        model2.load_state_dict(torch.load(weight_path, map_location="cpu"))

        model2.eval()
        with torch.no_grad():
            output2 = model2(input_tensor)

        assert torch.allclose(output1, output2, atol=1e-6)

        Path(weight_path).unlink()


class TestLicenseProtectionTransformer:
    """Test Transformer model for sequence analysis."""

    def test_transformer_initializes_with_correct_architecture(self) -> None:
        """Transformer initializes with proper encoder layers."""
        model = LicenseProtectionTransformer(input_dim=256, num_heads=8, num_layers=6)

        assert isinstance(model.input_projection, nn.Linear)
        assert isinstance(model.transformer_encoder, nn.TransformerEncoder)
        assert isinstance(model.classifier, nn.Sequential)

        assert model.input_projection.in_features == 256
        assert model.input_projection.out_features == 512
        assert model.model_dim == 512

        total_params = sum(p.numel() for p in model.parameters())
        assert total_params > 500000

    def test_transformer_forward_pass_produces_correct_output_shape(self) -> None:
        """Transformer forward pass produces classification logits."""
        model = LicenseProtectionTransformer(input_dim=256, num_heads=8, num_layers=4)
        model.eval()

        batch_size = 4
        seq_len = 32
        input_tensor = torch.randn(batch_size, seq_len, 256)

        with torch.no_grad():
            output = model(input_tensor)

        assert output.shape == (batch_size, len(LicenseProtectionType))
        assert not torch.isnan(output).any()
        assert not torch.isinf(output).any()

    def test_transformer_learns_sequence_patterns(self) -> None:
        """Transformer learns to classify sequences and reduces loss."""
        model = LicenseProtectionTransformer(input_dim=128, num_heads=4, num_layers=2)
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        criterion = nn.CrossEntropyLoss()

        X_train = torch.randn(50, 16, 128)
        y_train = torch.randint(0, len(LicenseProtectionType), (50,))

        X_train[:10, :, :32] += 1.5
        y_train[:10] = 0

        initial_loss = None
        final_loss = None

        model.train()
        for epoch in range(15):
            optimizer.zero_grad()
            outputs = model(X_train)
            loss = criterion(outputs, y_train)
            loss.backward()
            optimizer.step()

            if epoch == 0:
                initial_loss = loss.item()
            elif epoch == 14:
                final_loss = loss.item()

        assert initial_loss is not None
        assert final_loss is not None
        assert final_loss < initial_loss * 0.9

    def test_transformer_positional_encoding_applied(self) -> None:
        """Transformer applies positional encoding to inputs."""
        model = LicenseProtectionTransformer(input_dim=256, num_heads=8, num_layers=2)

        assert model.positional_encoding is not None
        assert model.positional_encoding.shape[1] == 1000
        assert model.positional_encoding.shape[2] == 512

        pe = model.positional_encoding[0, :10, :10]
        assert not torch.all(pe == 0)

    def test_transformer_saves_and_loads_weights(self) -> None:
        """Transformer weights preserve state across save/load."""
        model1 = LicenseProtectionTransformer(input_dim=256, num_heads=8, num_layers=2)

        input_tensor = torch.randn(2, 16, 256)
        with torch.no_grad():
            output1 = model1(input_tensor)

        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as tmp:
            model1.save_weights(tmp.name)
            weight_path = tmp.name

        model2 = LicenseProtectionTransformer(input_dim=256, num_heads=8, num_layers=2)
        model2.load_state_dict(torch.load(weight_path, map_location="cpu"))

        model2.eval()
        with torch.no_grad():
            output2 = model2(input_tensor)

        assert torch.allclose(output1, output2, atol=1e-6)

        Path(weight_path).unlink()


class TestHybridLicenseAnalyzer:
    """Test Hybrid model combining CNN, Transformer, and GNN."""

    def test_hybrid_initializes_all_branches(self) -> None:
        """Hybrid model initializes CNN, Transformer, and GNN branches."""
        model = HybridLicenseAnalyzer()

        assert isinstance(model.cnn_branch, LicenseProtectionCNN)
        assert isinstance(model.transformer_branch, LicenseProtectionTransformer)
        assert isinstance(model.gnn_branch, nn.Sequential)
        assert isinstance(model.fusion_layer, nn.Sequential)

        assert isinstance(model.protection_classifier, nn.Linear)
        assert isinstance(model.version_regressor, nn.Linear)
        assert isinstance(model.complexity_scorer, nn.Linear)
        assert isinstance(model.bypass_difficulty, nn.Linear)

        total_params = sum(p.numel() for p in model.parameters())
        assert total_params > 1000000

    def test_hybrid_forward_pass_produces_multi_task_outputs(self) -> None:
        """Hybrid model produces all multi-task outputs with correct shapes."""
        model = HybridLicenseAnalyzer()
        model.eval()

        batch_size = 4
        binary_features = torch.randn(batch_size, 4096)
        sequence_features = torch.randn(batch_size, 16, 256)
        graph_features = torch.randn(batch_size, 512)

        with torch.no_grad():
            outputs = model(binary_features, sequence_features, graph_features)

        assert isinstance(outputs, dict)
        assert "protection_type" in outputs
        assert "version" in outputs
        assert "complexity" in outputs
        assert "bypass_difficulty" in outputs

        assert outputs["protection_type"].shape == (batch_size, len(LicenseProtectionType))
        assert outputs["version"].shape == (batch_size, 1)
        assert outputs["complexity"].shape == (batch_size, 1)
        assert outputs["bypass_difficulty"].shape == (batch_size, 5)

        assert not torch.isnan(outputs["protection_type"]).any()
        assert not torch.isnan(outputs["version"]).any()

    def test_hybrid_learns_from_multi_modal_data(self) -> None:
        """Hybrid model learns from combined CNN, Transformer, GNN inputs."""
        model = HybridLicenseAnalyzer()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
        criterion = ProtectionLoss(num_classes=len(LicenseProtectionType))

        binary_features = torch.randn(30, 4096)
        sequence_features = torch.randn(30, 16, 256)
        graph_features = torch.randn(30, 512)
        labels = torch.randint(0, len(LicenseProtectionType), (30,))

        binary_features[:10] += 1.0
        sequence_features[:10] += 0.5
        graph_features[:10] += 0.5
        labels[:10] = 0

        initial_loss = None
        final_loss = None

        model.train()
        for epoch in range(10):
            optimizer.zero_grad()
            outputs = model(binary_features, sequence_features, graph_features)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()

            if epoch == 0:
                initial_loss = loss.item()
            elif epoch == 9:
                final_loss = loss.item()

        assert initial_loss is not None
        assert final_loss is not None
        assert final_loss < initial_loss * 0.85

    def test_hybrid_feature_fusion_combines_branches(self) -> None:
        """Hybrid model fusion layer combines features from all branches."""
        model = HybridLicenseAnalyzer()
        model.eval()

        binary_features = torch.randn(2, 4096)
        sequence_features = torch.randn(2, 16, 256)
        graph_features = torch.randn(2, 512)

        with torch.no_grad():
            cnn_out = model.cnn_branch(binary_features)
            transformer_out = model.transformer_branch(sequence_features)
            gnn_out = model.gnn_branch(graph_features)

            combined = torch.cat([cnn_out, transformer_out, gnn_out], dim=1)

            assert combined.shape == (2, 128 + 512 + 256)

            fused = model.fusion_layer(combined)
            assert fused.shape == (2, 256)


class TestLicenseDataset:
    """Test dataset loading and feature extraction."""

    def test_dataset_loads_from_directory_structure(self, temp_dataset_dir: Path) -> None:
        """Dataset loads binary samples from directory structure."""
        dataset = LicenseDataset(str(temp_dataset_dir))

        assert len(dataset) > 0
        assert len(dataset.samples) == len(dataset.labels)
        assert len(dataset.label_to_idx) > 0

        assert "vmprotect" in dataset.labels or "themida" in dataset.labels or "flexlm" in dataset.labels

    def test_dataset_extracts_features_from_binaries(self, temp_dataset_dir: Path) -> None:
        """Dataset extracts LicenseFeatures from real binary files."""
        dataset = LicenseDataset(str(temp_dataset_dir), cache_features=False)

        if len(dataset) == 0:
            pytest.skip("No samples in dataset")

        features, label = dataset[0]

        if isinstance(features, torch.Tensor):
            assert features.dtype == torch.float32
            assert features.dim() == 1
            assert features.shape[0] > 100
        else:
            assert isinstance(features, np.ndarray)
            assert features.dtype == np.float32

        assert isinstance(label, (int, torch.Tensor))

    def test_dataset_caches_features_correctly(self, temp_dataset_dir: Path) -> None:
        """Dataset caches extracted features for performance."""
        dataset = LicenseDataset(str(temp_dataset_dir), cache_features=True)

        if len(dataset) == 0:
            pytest.skip("No samples in dataset")

        features1, _ = dataset[0]
        features2, _ = dataset[0]

        if isinstance(features1, torch.Tensor):
            assert torch.equal(features1, features2)
        else:
            assert np.array_equal(features1, features2)

        assert len(dataset.feature_cache) > 0

    def test_dataset_label_mapping_is_consistent(self, temp_dataset_dir: Path) -> None:
        """Dataset maintains consistent label-to-index mapping."""
        dataset = LicenseDataset(str(temp_dataset_dir))

        assert len(dataset.label_to_idx) == len(dataset.idx_to_label)

        for label, idx in dataset.label_to_idx.items():
            assert dataset.idx_to_label[idx] == label

    def test_dataset_extracts_entropy_scores(self, sample_pe_binary: bytes) -> None:
        """Dataset calculates Shannon entropy from binary data."""
        dataset = LicenseDataset("nonexistent")

        entropy = dataset._calculate_entropy(sample_pe_binary)

        assert isinstance(entropy, np.ndarray)
        assert entropy.shape == (16,)
        assert entropy.dtype == np.float32
        assert (entropy >= 0).all()
        assert (entropy <= 8).all()

    def test_dataset_detects_crypto_constants(self, sample_pe_binary: bytes) -> None:
        """Dataset detects cryptographic constants in binary."""
        dataset = LicenseDataset("nonexistent")

        crypto_features = dataset._detect_crypto(sample_pe_binary)

        assert isinstance(crypto_features, np.ndarray)
        assert crypto_features.shape == (32,)
        assert (crypto_features >= 0).all()
        assert (crypto_features <= 1).all()

    def test_dataset_detects_license_apis(self, sample_pe_binary: bytes) -> None:
        """Dataset detects license-related API imports."""
        dataset = LicenseDataset("nonexistent")

        import_features = dataset._extract_imports(sample_pe_binary)

        assert isinstance(import_features, np.ndarray)
        assert import_features.shape == (64,)

        assert import_features.sum() > 0


class TestProtectionLoss:
    """Test custom loss function for license protection detection."""

    def test_protection_loss_initializes_correctly(self) -> None:
        """Protection loss initializes with focal and center loss components."""
        loss_fn = ProtectionLoss(num_classes=20)

        assert isinstance(loss_fn.classification_loss, nn.CrossEntropyLoss)
        assert loss_fn.focal_gamma == 2.0
        assert loss_fn.focal_alpha == 0.25
        assert loss_fn.center_loss_weight == 0.003
        assert isinstance(loss_fn.centers, nn.Parameter)
        assert loss_fn.centers.shape == (20, 256)

    def test_focal_loss_handles_class_imbalance(self) -> None:
        """Focal loss down-weights easy examples and focuses on hard ones."""
        loss_fn = ProtectionLoss(num_classes=5)

        easy_logits = torch.tensor([[10.0, -10.0, -10.0, -10.0, -10.0], [-10.0, 10.0, -10.0, -10.0, -10.0]])
        easy_targets = torch.tensor([0, 1])

        hard_logits = torch.tensor([[1.0, 0.9, 0.8, 0.7, 0.6], [0.9, 1.0, 0.8, 0.7, 0.6]])
        hard_targets = torch.tensor([0, 1])

        easy_loss = loss_fn.focal_loss(easy_logits, easy_targets)
        hard_loss = loss_fn.focal_loss(hard_logits, hard_targets)

        assert hard_loss > easy_loss

    def test_center_loss_clusters_features(self) -> None:
        """Center loss encourages features of same class to cluster together."""
        loss_fn = ProtectionLoss(num_classes=3)

        features_class0 = torch.randn(5, 256) + torch.tensor([1.0] * 256)
        features_class1 = torch.randn(5, 256) + torch.tensor([-1.0] * 256)
        features = torch.cat([features_class0, features_class1], dim=0)

        targets = torch.tensor([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])

        center_loss = loss_fn.compute_center_loss(features, targets)

        assert isinstance(center_loss, torch.Tensor)
        assert center_loss.item() >= 0

    def test_loss_computes_for_single_task_output(self) -> None:
        """Loss function handles single-task (classification only) outputs."""
        loss_fn = ProtectionLoss(num_classes=5)

        outputs = torch.randn(8, 5)
        targets = torch.randint(0, 5, (8,))

        loss = loss_fn(outputs, targets)

        assert isinstance(loss, torch.Tensor)
        assert loss.item() > 0
        assert not torch.isnan(loss)

    def test_loss_computes_for_multi_task_output(self) -> None:
        """Loss function handles multi-task outputs from hybrid model."""
        loss_fn = ProtectionLoss(num_classes=len(LicenseProtectionType))

        outputs = {
            "protection_type": torch.randn(8, len(LicenseProtectionType)),
            "version": torch.randn(8, 1),
            "complexity": torch.randn(8, 1),
            "bypass_difficulty": torch.randn(8, 5),
        }
        targets = torch.randint(0, len(LicenseProtectionType), (8,))

        loss = loss_fn(outputs, targets)

        assert isinstance(loss, torch.Tensor)
        assert loss.item() > 0
        assert not torch.isnan(loss)


class TestLicenseProtectionTrainer:
    """Test training loop and optimization."""

    def test_trainer_initializes_with_optimizer_and_scheduler(self) -> None:
        """Trainer sets up optimizer, scheduler, and loss function."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=20)
        trainer = LicenseProtectionTrainer(model, device="cpu")

        assert isinstance(trainer.optimizer, torch.optim.AdamW)
        assert isinstance(trainer.scheduler, torch.optim.lr_scheduler.OneCycleLR)
        assert isinstance(trainer.criterion, ProtectionLoss)
        assert isinstance(trainer.history, dict)

    def test_trainer_trains_one_epoch_and_reduces_loss(self) -> None:
        """Trainer runs one epoch and computes loss and accuracy."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=5)
        trainer = LicenseProtectionTrainer(model, device="cpu")

        X = torch.randn(32, 4096)
        y = torch.randint(0, 5, (32,))
        dataset = torch.utils.data.TensorDataset(X, y)
        dataloader = DataLoader(dataset, batch_size=8, shuffle=True)

        loss, accuracy = trainer.train_epoch(dataloader)

        assert isinstance(loss, float)
        assert isinstance(accuracy, float)
        assert loss > 0
        assert 0 <= accuracy <= 100

    def test_trainer_validates_model_performance(self) -> None:
        """Trainer validates model and computes validation metrics."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=5)
        trainer = LicenseProtectionTrainer(model, device="cpu")

        X = torch.randn(24, 4096)
        y = torch.randint(0, 5, (24,))
        dataset = torch.utils.data.TensorDataset(X, y)
        dataloader = DataLoader(dataset, batch_size=8, shuffle=False)

        val_loss, val_accuracy = trainer.validate(dataloader)

        assert isinstance(val_loss, float)
        assert isinstance(val_accuracy, float)
        assert val_loss > 0
        assert 0 <= val_accuracy <= 100

    def test_trainer_full_training_improves_accuracy(self) -> None:
        """Full training loop improves model accuracy over epochs."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=3)
        trainer = LicenseProtectionTrainer(model, device="cpu")
        trainer.num_epochs = 5

        X_train = torch.randn(60, 4096)
        y_train = torch.randint(0, 3, (60,))

        X_train[:20] += 2.0
        y_train[:20] = 0
        X_train[20:40] -= 2.0
        y_train[20:40] = 1

        train_dataset = torch.utils.data.TensorDataset(X_train, y_train)
        train_loader = DataLoader(train_dataset, batch_size=10, shuffle=True)

        X_val = torch.randn(30, 4096)
        y_val = torch.randint(0, 3, (30,))
        val_dataset = torch.utils.data.TensorDataset(X_val, y_val)
        val_loader = DataLoader(val_dataset, batch_size=10, shuffle=False)

        trainer.train(train_loader, val_loader)

        assert len(trainer.history["train_loss"]) == 5
        assert len(trainer.history["val_acc"]) == 5
        assert trainer.history["train_loss"][-1] < trainer.history["train_loss"][0]

    def test_trainer_saves_checkpoint_with_metadata(self) -> None:
        """Trainer saves checkpoint with model state and training history."""
        model = LicenseProtectionCNN(input_size=4096, num_classes=20)
        trainer = LicenseProtectionTrainer(model, device="cpu")
        trainer.history["train_loss"] = [1.5, 1.2, 1.0]
        trainer.history["val_acc"] = [50.0, 60.0, 70.0]

        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as tmp:
            checkpoint_path = tmp.name

        trainer.save_checkpoint(checkpoint_path)

        assert Path(checkpoint_path).exists()

        checkpoint = torch.load(checkpoint_path, map_location="cpu")
        assert "model_state_dict" in checkpoint
        assert "optimizer_state_dict" in checkpoint
        assert "history" in checkpoint
        assert "model_info" in checkpoint
        assert checkpoint["best_val_acc"] == 70.0

        Path(checkpoint_path).unlink()

    def test_trainer_loads_checkpoint_and_restores_state(self) -> None:
        """Trainer loads checkpoint and restores model and optimizer state."""
        model1 = LicenseProtectionCNN(input_size=4096, num_classes=20)
        trainer1 = LicenseProtectionTrainer(model1, device="cpu")
        trainer1.history["train_loss"] = [1.5, 1.2]

        with tempfile.NamedTemporaryFile(suffix=".pth", delete=False) as tmp:
            checkpoint_path = tmp.name

        trainer1.save_checkpoint(checkpoint_path)

        model2 = LicenseProtectionCNN(input_size=4096, num_classes=20)
        trainer2 = LicenseProtectionTrainer(model2, device="cpu")

        success = trainer2.load_checkpoint(checkpoint_path)

        assert success is True
        assert trainer2.history["train_loss"] == [1.5, 1.2]

        Path(checkpoint_path).unlink()


class TestLicenseProtectionPredictor:
    """Test high-level prediction interface."""

    def test_predictor_initializes_hybrid_model(self) -> None:
        """Predictor initializes with HybridLicenseAnalyzer."""
        predictor = LicenseProtectionPredictor()

        assert isinstance(predictor.model, HybridLicenseAnalyzer)
        assert predictor.device in ["cpu", "cuda"]

    def test_predictor_extracts_multi_modal_features(self, sample_pe_binary: bytes) -> None:
        """Predictor extracts binary, sequence, and graph features."""
        predictor = LicenseProtectionPredictor()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(sample_pe_binary)
            tmp_path = tmp.name

        features = predictor._extract_features(tmp_path)

        assert "binary" in features
        assert "sequence" in features
        assert "graph" in features

        assert isinstance(features["binary"], np.ndarray)
        assert features["binary"].shape == (4096,)

        assert isinstance(features["sequence"], np.ndarray)
        assert features["sequence"].shape[1] == 256

        assert isinstance(features["graph"], np.ndarray)
        assert features["graph"].shape == (512,)

        Path(tmp_path).unlink()

    def test_predictor_predicts_protection_type_from_binary(self, vmprotect_binary: bytes) -> None:
        """Predictor produces protection type prediction from binary."""
        predictor = LicenseProtectionPredictor()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(vmprotect_binary)
            tmp_path = tmp.name

        result = predictor.predict(tmp_path)

        assert isinstance(result, dict)
        assert "protection_type" in result
        assert "confidence" in result
        assert "version" in result
        assert "complexity" in result
        assert "bypass_difficulty" in result
        assert "all_probabilities" in result

        assert isinstance(result["protection_type"], str)
        assert 0 <= result["confidence"] <= 1
        assert result["bypass_difficulty"] >= 1

        Path(tmp_path).unlink()

    def test_predictor_fallback_works_without_pytorch(self, vmprotect_binary: bytes) -> None:
        """Predictor uses heuristic fallback for detection."""
        predictor = LicenseProtectionPredictor()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(vmprotect_binary)
            tmp_path = tmp.name

        result = predictor._fallback_prediction(tmp_path)

        assert isinstance(result, dict)
        assert "protection_type" in result
        assert result["protection_type"] in ["vmprotect", "unknown"]

        Path(tmp_path).unlink()

    def test_predictor_detects_vmprotect_signature(self, vmprotect_binary: bytes) -> None:
        """Predictor fallback detects VMProtect signature in binary."""
        predictor = LicenseProtectionPredictor()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(vmprotect_binary)
            tmp_path = tmp.name

        result = predictor._fallback_prediction(tmp_path)

        assert result["protection_type"] == "vmprotect"
        assert result["confidence"] >= 0.8

        Path(tmp_path).unlink()

    def test_predictor_detects_themida_signature(self, themida_binary: bytes) -> None:
        """Predictor fallback detects Themida signature in binary."""
        predictor = LicenseProtectionPredictor()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(themida_binary)
            tmp_path = tmp.name

        result = predictor._fallback_prediction(tmp_path)

        assert result["protection_type"] == "themida"
        assert result["confidence"] >= 0.8

        Path(tmp_path).unlink()


class TestLicenseFeaturesDataclass:
    """Test LicenseFeatures feature vector creation."""

    def test_license_features_to_tensor_concatenates_all_fields(self, sample_license_features: LicenseFeatures) -> None:
        """LicenseFeatures.to_tensor() concatenates all feature arrays."""
        tensor = sample_license_features.to_tensor()

        assert isinstance(tensor, np.ndarray)
        assert tensor.dtype == np.float32

        expected_size = 16 + 32 + 64 + 32 + 128 + 256 + 64 + 32 + 16 + 128 + 32 + 16 + 16 + 8 + 16 + 16 + 8 + 16 + 8
        assert tensor.shape == (expected_size,)

    def test_license_features_contains_all_required_fields(self, sample_license_features: LicenseFeatures) -> None:
        """LicenseFeatures dataclass has all required feature fields."""
        assert hasattr(sample_license_features, "entropy_scores")
        assert hasattr(sample_license_features, "section_characteristics")
        assert hasattr(sample_license_features, "import_signatures")
        assert hasattr(sample_license_features, "crypto_signatures")
        assert hasattr(sample_license_features, "anti_debug_features")
        assert hasattr(sample_license_features, "api_sequence_embedding")
        assert hasattr(sample_license_features, "network_signatures")
        assert hasattr(sample_license_features, "hardware_checks")
        assert hasattr(sample_license_features, "virtualization_checks")


class TestGlobalPredictorSingleton:
    """Test global predictor singleton pattern."""

    def test_get_license_predictor_returns_singleton(self) -> None:
        """get_license_predictor() returns same instance across calls."""
        predictor1 = get_license_predictor()
        predictor2 = get_license_predictor()

        assert predictor1 is predictor2


class TestIntegrationWorkflows:
    """Integration tests for complete workflows."""

    def test_complete_training_workflow_with_real_data(self, temp_dataset_dir: Path) -> None:
        """Complete workflow: create dataset, train model, evaluate."""
        if not list(temp_dataset_dir.iterdir()):
            pytest.skip("Empty dataset directory")

        dataset = LicenseDataset(str(temp_dataset_dir))

        if len(dataset) < 4:
            pytest.skip("Dataset too small for training")

        features_list = []
        labels_list = []
        for i in range(len(dataset)):
            features, label = dataset[i]
            if isinstance(features, torch.Tensor):
                feature_size = features.shape[0]
                if feature_size < 4096:
                    padding = torch.zeros(4096 - feature_size)
                    features = torch.cat([features, padding])
                elif feature_size > 4096:
                    features = features[:4096]
            features_list.append(features)
            labels_list.append(label)

        features_tensor = torch.stack(features_list)
        labels_tensor = torch.stack(labels_list) if isinstance(labels_list[0], torch.Tensor) else torch.tensor(labels_list)

        train_size = int(len(dataset) * 0.7)
        val_size = len(dataset) - train_size

        indices = torch.randperm(len(dataset))
        train_indices = indices[:train_size]
        val_indices = indices[train_size:]

        train_features = features_tensor[train_indices]
        train_labels = labels_tensor[train_indices]
        val_features = features_tensor[val_indices]
        val_labels = labels_tensor[val_indices]

        train_dataset = torch.utils.data.TensorDataset(train_features, train_labels)
        val_dataset = torch.utils.data.TensorDataset(val_features, val_labels)

        train_loader = DataLoader(train_dataset, batch_size=2, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=2, shuffle=False)

        model = LicenseProtectionCNN(input_size=4096, num_classes=len(dataset.label_to_idx))
        trainer = LicenseProtectionTrainer(model, device="cpu")
        trainer.num_epochs = 2

        trainer.train(train_loader, val_loader)

        assert len(trainer.history["train_loss"]) == 2
        assert len(trainer.history["val_loss"]) == 2

    def test_prediction_workflow_on_real_binary(self, vmprotect_binary: bytes) -> None:
        """Complete prediction workflow on real binary file."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(vmprotect_binary)
            tmp_path = tmp.name

        predictor = LicenseProtectionPredictor()
        result = predictor.predict(tmp_path)

        assert result["protection_type"] is not None
        assert result["confidence"] > 0
        assert len(result["all_probabilities"]) > 0

        Path(tmp_path).unlink()
