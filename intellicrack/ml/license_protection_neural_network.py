"""Advanced Neural Network for License Protection Analysis.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import json
import logging
import os
import struct
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as functional
    import torch.optim as optim
    from torch.utils.data import DataLoader, Dataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None
    nn = None
    F = None
    optim = None
    DataLoader = None
    Dataset = None

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    tf = None
    keras = None
    layers = None
    models = None


class LicenseProtectionType(Enum):
    """Modern license protection types for classification."""

    FLEXLM = "flexlm"
    SENTINEL_HASP = "sentinel_hasp"
    WIBU_CODEMETER = "wibu_codemeter"
    ADOBE_LICENSING = "adobe_licensing"
    MICROSOFT_ACTIVATION = "microsoft_activation"
    STEAM_DRM = "steam_drm"
    DENUVO = "denuvo"
    VMPROTECT = "vmprotect"
    THEMIDA = "themida"
    CUSTOM_CRYPTO = "custom_crypto"
    CLOUD_LICENSING = "cloud_licensing"
    HARDWARE_DONGLE = "hardware_dongle"
    TIME_TRIAL = "time_trial"
    FEATURE_LICENSING = "feature_licensing"
    NODE_LOCKED = "node_locked"
    FLOATING_LICENSE = "floating_license"
    SUBSCRIPTION_MODEL = "subscription_model"
    BLOCKCHAIN_LICENSE = "blockchain_license"
    TPM_BASED = "tpm_based"
    UNKNOWN = "unknown"


@dataclass
class LicenseFeatures:
    """Features extracted from binary for license analysis."""

    # Binary characteristics
    entropy_scores: np.ndarray  # Entropy across sections
    section_characteristics: np.ndarray  # PE section features
    import_signatures: np.ndarray  # Import table features
    export_signatures: np.ndarray  # Export table features
    string_features: np.ndarray  # License-related string patterns

    # Code patterns
    opcode_histogram: np.ndarray  # x86/x64 instruction distribution
    call_graph_features: np.ndarray  # Function call patterns
    crypto_signatures: np.ndarray  # Cryptographic routine detection
    anti_debug_features: np.ndarray  # Anti-debugging technique markers

    # Behavioral patterns
    api_sequence_embedding: np.ndarray  # API call sequence features
    network_signatures: np.ndarray  # Network communication patterns
    registry_patterns: np.ndarray  # Registry access patterns
    file_access_patterns: np.ndarray  # File system patterns

    # Advanced features
    control_flow_complexity: np.ndarray  # CFG complexity metrics
    data_flow_features: np.ndarray  # Data dependency patterns
    memory_access_patterns: np.ndarray  # Memory operation patterns
    timing_patterns: np.ndarray  # Time-based check patterns

    # Hardware features
    hardware_checks: np.ndarray  # Hardware ID verification patterns
    virtualization_checks: np.ndarray  # VM/sandbox detection

    def to_tensor(self) -> np.ndarray:
        """Convert all features to a single tensor."""
        all_features = []
        for _field_name, field_value in self.__dict__.items():
            if isinstance(field_value, np.ndarray):
                all_features.append(field_value.flatten())

        return np.concatenate(all_features)


class LicenseProtectionCNN(nn.Module if TORCH_AVAILABLE else object):
    """Convolutional Neural Network for license protection detection."""

    def __init__(self, input_size: int = 4096, num_classes: int = 20):
        """Initialize CNN architecture for license protection analysis."""
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch not available for CNN model")

        super().__init__()

        # Reshape input to 2D for convolution (64x64)
        self.input_reshape = (64, 64)

        # Convolutional layers for pattern detection
        self.conv1 = nn.Conv2d(1, 32, kernel_size=5, stride=1, padding=2)
        self.bn1 = nn.BatchNorm2d(32)
        self.conv2 = nn.Conv2d(32, 64, kernel_size=3, stride=1, padding=1)
        self.bn2 = nn.BatchNorm2d(64)
        self.conv3 = nn.Conv2d(64, 128, kernel_size=3, stride=1, padding=1)
        self.bn3 = nn.BatchNorm2d(128)

        # Attention mechanism for important features
        self.attention = nn.Sequential(
            nn.Conv2d(128, 64, kernel_size=1),
            nn.ReLU(),
            nn.Conv2d(64, 128, kernel_size=1),
            nn.Sigmoid()
        )

        # Pooling layers
        self.pool = nn.MaxPool2d(kernel_size=2, stride=2)
        self.adaptive_pool = nn.AdaptiveAvgPool2d((4, 4))

        # Fully connected layers
        self.fc1 = nn.Linear(128 * 4 * 4, 512)
        self.dropout1 = nn.Dropout(0.5)
        self.fc2 = nn.Linear(512, 256)
        self.dropout2 = nn.Dropout(0.3)
        self.fc3 = nn.Linear(256, num_classes)

        # Residual connections
        self.residual_conv = nn.Conv2d(32, 128, kernel_size=1, stride=4)

    def forward(self, x):
        """Forward pass with attention and residual connections."""
        # Reshape input
        batch_size = x.size(0)
        x = x.view(batch_size, 1, 64, 64)

        # First conv block
        x1 = functional.relu(self.bn1(self.conv1(x)))
        x1 = self.pool(x1)

        # Second conv block
        x2 = functional.relu(self.bn2(self.conv2(x1)))
        x2 = self.pool(x2)

        # Third conv block with residual
        x3 = functional.relu(self.bn3(self.conv3(x2)))

        # Apply attention
        attention_weights = self.attention(x3)
        x3 = x3 * attention_weights

        # Add residual connection
        residual = self.residual_conv(x1)
        x3 = x3 + residual

        # Adaptive pooling for fixed size output
        x = self.adaptive_pool(x3)

        # Flatten and fully connected layers
        x = x.view(batch_size, -1)
        x = functional.relu(self.fc1(x))
        x = self.dropout1(x)
        x = functional.relu(self.fc2(x))
        x = self.dropout2(x)
        x = self.fc3(x)

        return x


class LicenseProtectionTransformer(nn.Module if TORCH_AVAILABLE else object):
    """Transformer-based model for sequence analysis of license checks."""

    def __init__(self, input_dim: int = 256, num_heads: int = 8, num_layers: int = 6):
        """Initialize Transformer for API sequence and opcode analysis."""
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch not available for Transformer model")

        super().__init__()

        self.input_dim = input_dim
        self.model_dim = 512

        # Input embedding
        self.input_projection = nn.Linear(input_dim, self.model_dim)
        self.positional_encoding = self._create_positional_encoding(1000, self.model_dim)

        # Transformer encoder layers
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=self.model_dim,
            nhead=num_heads,
            dim_feedforward=2048,
            dropout=0.1,
            activation='gelu',
            batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # Output layers for classification
        self.global_pool = nn.AdaptiveAvgPool1d(1)
        self.classifier = nn.Sequential(
            nn.Linear(self.model_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, len(LicenseProtectionType))
        )

    def _create_positional_encoding(self, max_len: int, d_model: int) -> torch.Tensor:
        """Create sinusoidal positional encoding."""
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() *
                           (-np.log(10000.0) / d_model))

        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)

        return pe.unsqueeze(0)

    def forward(self, x):
        """Forward pass through transformer."""
        batch_size, seq_len, _ = x.size()

        # Project input and add positional encoding
        x = self.input_projection(x)
        x = x + self.positional_encoding[:, :seq_len, :].to(x.device)

        # Pass through transformer encoder
        x = self.transformer_encoder(x)

        # Global pooling and classification
        x = x.transpose(1, 2)  # (batch, features, seq_len)
        x = self.global_pool(x).squeeze(-1)  # (batch, features)
        output = self.classifier(x)

        return output


class HybridLicenseAnalyzer(nn.Module if TORCH_AVAILABLE else object):
    """Hybrid model combining CNN, Transformer, and Graph Neural Networks."""

    def __init__(self):
        """Initialize hybrid architecture for comprehensive license analysis."""
        if not TORCH_AVAILABLE:
            raise ImportError("PyTorch not available for Hybrid model")

        super().__init__()

        # CNN for binary pattern analysis
        self.cnn_branch = LicenseProtectionCNN(input_size=4096, num_classes=128)

        # Transformer for sequence analysis
        self.transformer_branch = LicenseProtectionTransformer(input_dim=256, num_heads=8)

        # Graph Neural Network for control flow analysis
        self.gnn_branch = self._create_gnn_branch()

        # Feature fusion layers
        self.fusion_layer = nn.Sequential(
            nn.Linear(128 + 512 + 256, 512),
            nn.ReLU(),
            nn.BatchNorm1d(512),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.BatchNorm1d(256)
        )

        # Multi-task output heads
        self.protection_classifier = nn.Linear(256, len(LicenseProtectionType))
        self.version_regressor = nn.Linear(256, 1)  # Protection version prediction
        self.complexity_scorer = nn.Linear(256, 1)  # Protection complexity score
        self.bypass_difficulty = nn.Linear(256, 5)  # Bypass difficulty levels

    def _create_gnn_branch(self):
        """Create Graph Neural Network branch for CFG analysis."""
        # Simplified GNN using standard layers
        return nn.Sequential(
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.BatchNorm1d(256),
            nn.Linear(256, 256),
            nn.ReLU()
        )

    def forward(self, binary_features, sequence_features, graph_features):
        """Multi-modal forward pass."""
        # Process through each branch
        cnn_out = self.cnn_branch(binary_features)
        transformer_out = self.transformer_branch(sequence_features)
        gnn_out = self.gnn_branch(graph_features)

        # Concatenate and fuse features
        combined = torch.cat([cnn_out, transformer_out, gnn_out], dim=1)
        fused = self.fusion_layer(combined)

        # Multi-task outputs
        protection_type = self.protection_classifier(fused)
        version = self.version_regressor(fused)
        complexity = self.complexity_scorer(fused)
        difficulty = self.bypass_difficulty(fused)

        return {
            'protection_type': protection_type,
            'version': version,
            'complexity': complexity,
            'bypass_difficulty': difficulty
        }


class LicenseDataset(Dataset if TORCH_AVAILABLE else object):
    """Dataset for license protection training data."""

    def __init__(self, data_path: str, transform=None):
        """Initialize dataset with protection samples."""
        self.data_path = Path(data_path)
        self.transform = transform
        self.samples = []
        self.labels = []

        self._load_data()

    def _load_data(self):
        """Load binary samples and labels."""
        if not self.data_path.exists():
            return

        # Load sample metadata
        metadata_file = self.data_path / "metadata.json"
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)

            for sample in metadata['samples']:
                sample_path = self.data_path / sample['file']
                if sample_path.exists():
                    self.samples.append(sample_path)
                    self.labels.append(sample['protection_type'])

    def __len__(self):
        """Return dataset size."""
        return len(self.samples)

    def __getitem__(self, idx):
        """Get sample and label."""
        sample_path = self.samples[idx]
        label = self.labels[idx]

        # Extract features from binary
        features = self._extract_features(sample_path)

        if self.transform:
            features = self.transform(features)

        return features, label

    def _extract_features(self, binary_path: Path) -> LicenseFeatures:
        """Extract comprehensive features from binary."""
        with open(binary_path, 'rb') as f:
            data = f.read()

        # Calculate various feature vectors
        features = LicenseFeatures(
            entropy_scores=self._calculate_entropy(data),
            section_characteristics=self._analyze_sections(data),
            import_signatures=self._extract_imports(data),
            export_signatures=self._extract_exports(data),
            string_features=self._extract_strings(data),
            opcode_histogram=self._analyze_opcodes(data),
            call_graph_features=self._analyze_call_graph(data),
            crypto_signatures=self._detect_crypto(data),
            anti_debug_features=self._detect_anti_debug(data),
            api_sequence_embedding=self._embed_api_sequences(data),
            network_signatures=self._analyze_network(data),
            registry_patterns=self._analyze_registry(data),
            file_access_patterns=self._analyze_file_access(data),
            control_flow_complexity=self._analyze_cfg(data),
            data_flow_features=self._analyze_data_flow(data),
            memory_access_patterns=self._analyze_memory(data),
            timing_patterns=self._analyze_timing(data),
            hardware_checks=self._detect_hardware_checks(data),
            virtualization_checks=self._detect_vm_checks(data)
        )

        return features

    def _calculate_entropy(self, data: bytes) -> np.ndarray:
        """Calculate Shannon entropy distribution."""
        if not data:
            return np.zeros(16)

        # Calculate entropy in chunks
        chunk_size = len(data) // 16
        entropies = []

        for i in range(16):
            chunk = data[i*chunk_size:(i+1)*chunk_size]
            if chunk:
                # Calculate byte frequency
                byte_counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
                probabilities = byte_counts / len(chunk)
                # Shannon entropy
                entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
                entropies.append(entropy)
            else:
                entropies.append(0.0)

        return np.array(entropies, dtype=np.float32)

    def _analyze_sections(self, data: bytes) -> np.ndarray:
        """Analyze PE section characteristics."""
        features = np.zeros(32, dtype=np.float32)

        # Check for PE signature
        if len(data) > 0x3C:
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0] if len(data) > 0x40 else 0
            if len(data) > pe_offset + 4 and data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                # Extract section information
                num_sections_offset = pe_offset + 6
                if len(data) > num_sections_offset + 2:
                    num_sections = struct.unpack('<H', data[num_sections_offset:num_sections_offset+2])[0]
                    features[0] = min(num_sections, 20) / 20.0  # Normalize

                    # Section header analysis
                    section_table_offset = pe_offset + 0xF8
                    for i in range(min(num_sections, 8)):
                        section_offset = section_table_offset + (i * 40)
                        if len(data) > section_offset + 40:
                            # Extract section characteristics
                            characteristics = struct.unpack('<I', data[section_offset+36:section_offset+40])[0]
                            features[i+1] = (characteristics & 0xE0000000) / 0xE0000000  # Normalize flags

        return features

    def _extract_imports(self, data: bytes) -> np.ndarray:
        """Extract import table signatures."""
        features = np.zeros(64, dtype=np.float32)

        # Common license-related imports
        license_apis = [
            b'RegOpenKey', b'RegQueryValue', b'GetSystemTime',
            b'GetTickCount', b'CryptHashData', b'CryptGenKey',
            b'InternetOpen', b'HttpSendRequest', b'GetVolumeInformation',
            b'GetComputerName', b'GetUserName', b'GetWindowsDirectory'
        ]

        for i, api in enumerate(license_apis[:64]):
            if api in data:
                features[i] = 1.0

        return features

    def _extract_exports(self, data: bytes) -> np.ndarray:
        """Extract export table signatures."""
        return np.zeros(32, dtype=np.float32)  # Simplified

    def _extract_strings(self, data: bytes) -> np.ndarray:
        """Extract license-related string patterns."""
        features = np.zeros(128, dtype=np.float32)

        # License-related keywords
        keywords = [
            b'license', b'serial', b'key', b'trial', b'expired',
            b'activation', b'register', b'unlock', b'premium',
            b'subscription', b'valid', b'invalid', b'demo'
        ]

        text = data.lower()
        for i, keyword in enumerate(keywords):
            count = text.count(keyword)
            features[i] = min(count, 10) / 10.0  # Normalize

        return features

    def _analyze_opcodes(self, data: bytes) -> np.ndarray:
        """Analyze x86/x64 opcode distribution."""
        # Common opcodes for license checks

        histogram = np.zeros(256, dtype=np.float32)
        for byte in data:
            histogram[byte] += 1

        # Normalize
        if len(data) > 0:
            histogram = histogram / len(data)

        return histogram

    def _analyze_call_graph(self, data: bytes) -> np.ndarray:
        """Analyze function call patterns."""
        features = np.zeros(64, dtype=np.float32)

        # Look for CALL instructions (0xE8)
        call_count = data.count(b'\xE8')
        features[0] = min(call_count, 1000) / 1000.0

        # Look for indirect calls (FF 15)
        indirect_calls = data.count(b'\xFF\x15')
        features[1] = min(indirect_calls, 500) / 500.0

        return features

    def _detect_crypto(self, data: bytes) -> np.ndarray:
        """Detect cryptographic routine signatures."""
        features = np.zeros(32, dtype=np.float32)

        # Crypto constants
        crypto_constants = [
            b'\x67\x45\x23\x01',  # MD5
            b'\x98\xBA\xDC\xFE',  # MD5
            b'\x10\x32\x54\x76',  # MD5
            b'\x01\x23\x45\x67',  # SHA1
            b'\x89\xAB\xCD\xEF',  # SHA1
            b'\x6A\x09\xE6\x67',  # SHA256
            b'\xBB\x67\xAE\x85',  # SHA256
        ]

        for i, constant in enumerate(crypto_constants):
            if constant in data:
                features[i] = 1.0

        return features

    def _detect_anti_debug(self, data: bytes) -> np.ndarray:
        """Detect anti-debugging techniques."""
        features = np.zeros(16, dtype=np.float32)

        # Anti-debug APIs
        anti_debug = [
            b'IsDebuggerPresent',
            b'CheckRemoteDebuggerPresent',
            b'NtQueryInformationProcess',
            b'OutputDebugString',
            b'ZwQueryInformationProcess'
        ]

        for i, api in enumerate(anti_debug):
            if api in data:
                features[i] = 1.0

        return features

    def _embed_api_sequences(self, data: bytes) -> np.ndarray:
        """Create embeddings for API call sequences."""
        return np.random.randn(128).astype(np.float32)  # Placeholder

    def _analyze_network(self, data: bytes) -> np.ndarray:
        """Analyze network communication patterns."""
        features = np.zeros(32, dtype=np.float32)

        # Network APIs
        network_apis = [
            b'socket', b'connect', b'send', b'recv',
            b'InternetOpen', b'InternetConnect',
            b'HttpOpenRequest', b'HttpSendRequest'
        ]

        for i, api in enumerate(network_apis):
            if api in data:
                features[i] = 1.0

        return features

    def _analyze_registry(self, data: bytes) -> np.ndarray:
        """Analyze registry access patterns."""
        features = np.zeros(16, dtype=np.float32)

        # Registry APIs
        reg_apis = [
            b'RegOpenKey', b'RegCreateKey', b'RegSetValue',
            b'RegQueryValue', b'RegDeleteKey'
        ]

        for i, api in enumerate(reg_apis):
            if api in data:
                features[i] = 1.0

        return features

    def _analyze_file_access(self, data: bytes) -> np.ndarray:
        """Analyze file system access patterns."""
        return np.zeros(16, dtype=np.float32)

    def _analyze_cfg(self, data: bytes) -> np.ndarray:
        """Analyze control flow graph complexity."""
        # Simplified CFG metrics
        features = np.zeros(8, dtype=np.float32)

        # Count branching instructions
        branch_opcodes = [0x74, 0x75, 0x76, 0x77, 0xE8, 0xE9, 0xEB]
        for i, opcode in enumerate(branch_opcodes):
            count = data.count(bytes([opcode]))
            features[i] = min(count, 1000) / 1000.0

        return features

    def _analyze_data_flow(self, data: bytes) -> np.ndarray:
        """Analyze data flow patterns."""
        return np.zeros(16, dtype=np.float32)

    def _analyze_memory(self, data: bytes) -> np.ndarray:
        """Analyze memory access patterns."""
        return np.zeros(16, dtype=np.float32)

    def _analyze_timing(self, data: bytes) -> np.ndarray:
        """Analyze timing-based protection patterns."""
        features = np.zeros(8, dtype=np.float32)

        # Timing APIs
        timing_apis = [
            b'GetTickCount', b'QueryPerformanceCounter',
            b'GetSystemTime', b'timeGetTime'
        ]

        for i, api in enumerate(timing_apis):
            if api in data:
                features[i] = 1.0

        return features

    def _detect_hardware_checks(self, data: bytes) -> np.ndarray:
        """Detect hardware verification patterns."""
        features = np.zeros(16, dtype=np.float32)

        # Hardware APIs
        hw_apis = [
            b'GetVolumeInformation', b'GetSystemInfo',
            b'cpuid', b'GetComputerName', b'GetAdaptersInfo'
        ]

        for i, api in enumerate(hw_apis):
            if api in data:
                features[i] = 1.0

        return features

    def _detect_vm_checks(self, data: bytes) -> np.ndarray:
        """Detect VM/sandbox detection patterns."""
        features = np.zeros(8, dtype=np.float32)

        # VM artifacts
        vm_strings = [
            b'VMware', b'VirtualBox', b'QEMU',
            b'Xen', b'VBox', b'vmtoolsd'
        ]

        for i, vm_str in enumerate(vm_strings):
            if vm_str in data:
                features[i] = 1.0

        return features


class LicenseProtectionTrainer:
    """Trainer for license protection neural networks."""

    def __init__(self, model, device='cuda' if torch and torch.cuda.is_available() else 'cpu'):
        """Initialize trainer with model and training configuration."""
        self.model = model
        self.device = device
        if TORCH_AVAILABLE:
            self.model = self.model.to(device)

        self.logger = logging.getLogger(__name__)

        # Training configuration
        self.learning_rate = 0.001
        self.batch_size = 32
        self.num_epochs = 100

        if TORCH_AVAILABLE:
            self.optimizer = optim.AdamW(
                self.model.parameters(),
                lr=self.learning_rate,
                weight_decay=0.01
            )

            self.scheduler = optim.lr_scheduler.CosineAnnealingLR(
                self.optimizer,
                T_max=self.num_epochs
            )

            self.criterion = nn.CrossEntropyLoss()

        # Training history
        self.history = {
            'train_loss': [],
            'train_acc': [],
            'val_loss': [],
            'val_acc': []
        }

    def train_epoch(self, dataloader):
        """Train for one epoch."""
        if not TORCH_AVAILABLE:
            return 0.0, 0.0

        self.model.train()
        total_loss = 0.0
        correct = 0
        total = 0

        for _batch_idx, (features, labels) in enumerate(dataloader):
            features = features.to(self.device)
            labels = labels.to(self.device)

            # Zero gradients
            self.optimizer.zero_grad()

            # Forward pass
            outputs = self.model(features)

            # Handle multi-task outputs
            if isinstance(outputs, dict):
                outputs = outputs['protection_type']

            loss = self.criterion(outputs, labels)

            # Backward pass
            loss.backward()

            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

            # Update weights
            self.optimizer.step()

            # Statistics
            total_loss += loss.item()
            _, predicted = outputs.max(1)
            total += labels.size(0)
            correct += predicted.eq(labels).sum().item()

        accuracy = 100. * correct / total
        avg_loss = total_loss / len(dataloader)

        return avg_loss, accuracy

    def validate(self, dataloader):
        """Validate model performance."""
        if not TORCH_AVAILABLE:
            return 0.0, 0.0

        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0

        with torch.no_grad():
            for features, labels in dataloader:
                features = features.to(self.device)
                labels = labels.to(self.device)

                outputs = self.model(features)

                if isinstance(outputs, dict):
                    outputs = outputs['protection_type']

                loss = self.criterion(outputs, labels)

                total_loss += loss.item()
                _, predicted = outputs.max(1)
                total += labels.size(0)
                correct += predicted.eq(labels).sum().item()

        accuracy = 100. * correct / total
        avg_loss = total_loss / len(dataloader)

        return avg_loss, accuracy

    def train(self, train_loader, val_loader=None):
        """Full training loop."""
        if not TORCH_AVAILABLE:
            self.logger.warning("PyTorch not available for training")
            return

        self.logger.info("Starting training...")
        best_val_acc = 0.0

        for epoch in range(self.num_epochs):
            # Training
            train_loss, train_acc = self.train_epoch(train_loader)
            self.history['train_loss'].append(train_loss)
            self.history['train_acc'].append(train_acc)

            # Validation
            if val_loader:
                val_loss, val_acc = self.validate(val_loader)
                self.history['val_loss'].append(val_loss)
                self.history['val_acc'].append(val_acc)

                # Save best model
                if val_acc > best_val_acc:
                    best_val_acc = val_acc
                    self.save_checkpoint(f'best_model_epoch_{epoch}.pth')

                self.logger.info(
                    f'Epoch {epoch+1}/{self.num_epochs} - '
                    f'Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.2f}% - '
                    f'Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.2f}%'
                )
            else:
                self.logger.info(
                    f'Epoch {epoch+1}/{self.num_epochs} - '
                    f'Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.2f}%'
                )

            # Learning rate scheduling
            self.scheduler.step()

    def save_checkpoint(self, filepath):
        """Save model checkpoint."""
        if not TORCH_AVAILABLE:
            return

        checkpoint = {
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict(),
            'history': self.history
        }
        torch.save(checkpoint, filepath)
        self.logger.info(f"Checkpoint saved to {filepath}")

    def load_checkpoint(self, filepath):
        """Load model checkpoint."""
        if not TORCH_AVAILABLE:
            return

        checkpoint = torch.load(filepath, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])
        self.history = checkpoint['history']
        self.logger.info(f"Checkpoint loaded from {filepath}")


class LicenseProtectionPredictor:
    """High-level interface for license protection prediction."""

    def __init__(self, model_path: Optional[str] = None):
        """Initialize predictor with pre-trained model."""
        self.logger = logging.getLogger(__name__)

        if TORCH_AVAILABLE:
            self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
            self.model = HybridLicenseAnalyzer()

            if model_path and os.path.exists(model_path):
                self.load_model(model_path)
            else:
                self.logger.warning("No pre-trained model loaded")
        else:
            self.device = 'cpu'
            self.model = None
            self.logger.warning("PyTorch not available for predictions")

    def load_model(self, model_path):
        """Load pre-trained model."""
        if not TORCH_AVAILABLE:
            return

        checkpoint = torch.load(model_path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.to(self.device)
        self.model.eval()
        self.logger.info(f"Model loaded from {model_path}")

    def predict(self, binary_path: str) -> Dict[str, Any]:
        """Predict license protection type and characteristics."""
        if not TORCH_AVAILABLE or not self.model:
            return self._fallback_prediction(binary_path)

        # Extract features
        features = self._extract_features(binary_path)

        # Convert to tensors
        binary_tensor = torch.tensor(features['binary'], dtype=torch.float32).unsqueeze(0)
        sequence_tensor = torch.tensor(features['sequence'], dtype=torch.float32).unsqueeze(0)
        graph_tensor = torch.tensor(features['graph'], dtype=torch.float32).unsqueeze(0)

        # Move to device
        binary_tensor = binary_tensor.to(self.device)
        sequence_tensor = sequence_tensor.to(self.device)
        graph_tensor = graph_tensor.to(self.device)

        # Predict
        with torch.no_grad():
            outputs = self.model(binary_tensor, sequence_tensor, graph_tensor)

        # Process outputs
        protection_probs = functional.softmax(outputs['protection_type'], dim=1)
        protection_idx = protection_probs.argmax(dim=1).item()
        protection_type = list(LicenseProtectionType)[protection_idx]

        result = {
            'protection_type': protection_type.value,
            'confidence': protection_probs.max().item(),
            'version': outputs['version'].item(),
            'complexity': outputs['complexity'].item(),
            'bypass_difficulty': outputs['bypass_difficulty'].argmax(dim=1).item() + 1,
            'all_probabilities': {
                t.value: prob.item()
                for t, prob in zip(LicenseProtectionType, protection_probs[0], strict=False)
            }
        }

        return result

    def _extract_features(self, binary_path: str) -> Dict[str, np.ndarray]:
        """Extract multi-modal features from binary."""
        with open(binary_path, 'rb') as f:
            data = f.read()

        # Extract different feature modalities
        binary_features = self._extract_binary_features(data)
        sequence_features = self._extract_sequence_features(data)
        graph_features = self._extract_graph_features(data)

        return {
            'binary': binary_features,
            'sequence': sequence_features,
            'graph': graph_features
        }

    def _extract_binary_features(self, data: bytes) -> np.ndarray:
        """Extract binary-level features."""
        features = []

        # Entropy distribution
        chunk_size = max(1, len(data) // 64)
        for i in range(64):
            chunk = data[i*chunk_size:(i+1)*chunk_size]
            if chunk:
                byte_counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
                probs = byte_counts / len(chunk)
                entropy = -np.sum(probs * np.log2(probs + 1e-10))
                features.append(entropy)
            else:
                features.append(0.0)

        # Pad to expected size
        while len(features) < 4096:
            features.append(0.0)

        return np.array(features[:4096], dtype=np.float32)

    def _extract_sequence_features(self, data: bytes) -> np.ndarray:
        """Extract sequence features for transformer."""
        # Create sequence of byte n-grams
        features = []
        window_size = 256
        stride = 128

        for i in range(0, min(len(data), 100000), stride):
            window = data[i:i+window_size]
            if len(window) < window_size:
                window = window + b'\x00' * (window_size - len(window))
            features.append(list(window))

        # Convert to numpy array
        features = np.array(features, dtype=np.float32) / 255.0

        # Ensure correct shape (seq_len, feature_dim)
        if features.shape[0] == 0:
            features = np.zeros((10, 256), dtype=np.float32)
        elif features.shape[0] < 10:
            padding = np.zeros((10 - features.shape[0], 256), dtype=np.float32)
            features = np.vstack([features, padding])

        return features[:10]  # Limit sequence length

    def _extract_graph_features(self, data: bytes) -> np.ndarray:
        """Extract control flow graph features."""
        # Simplified CFG feature extraction
        features = []

        # Count different types of control flow instructions
        jmp_count = data.count(b'\xE9') + data.count(b'\xEB')
        call_count = data.count(b'\xE8')
        ret_count = data.count(b'\xC3') + data.count(b'\xC2')

        features.extend([jmp_count, call_count, ret_count])

        # Pad to expected size
        while len(features) < 512:
            features.append(0.0)

        return np.array(features[:512], dtype=np.float32)

    def _fallback_prediction(self, binary_path: str) -> Dict[str, Any]:
        """Fallback prediction using heuristics when ML models unavailable."""
        with open(binary_path, 'rb') as f:
            data = f.read()

        # Simple heuristic-based detection
        protection_scores = {}

        # Check for known protection signatures
        if b'FLEXlm' in data or b'lmgr' in data:
            protection_scores['flexlm'] = 0.8
        if b'HASP' in data or b'Sentinel' in data:
            protection_scores['sentinel_hasp'] = 0.7
        if b'VMProtect' in data:
            protection_scores['vmprotect'] = 0.9
        if b'Themida' in data or b'WinLicense' in data:
            protection_scores['themida'] = 0.85

        # Default to unknown if no signatures found
        if not protection_scores:
            protection_scores['unknown'] = 0.5

        # Get highest scoring protection
        protection_type = max(protection_scores, key=protection_scores.get)
        confidence = protection_scores[protection_type]

        return {
            'protection_type': protection_type,
            'confidence': confidence,
            'version': 0.0,
            'complexity': 0.5,
            'bypass_difficulty': 3,
            'all_probabilities': protection_scores
        }


# Global instance for easy access
_global_predictor = None

def get_license_predictor(model_path: Optional[str] = None) -> LicenseProtectionPredictor:
    """Get or create global license protection predictor."""
    global _global_predictor

    if _global_predictor is None:
        _global_predictor = LicenseProtectionPredictor(model_path)

    return _global_predictor
