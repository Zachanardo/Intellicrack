"""
This file is part of Intellicrack.
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
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Neural network-based fuzzing with deep learning for intelligent input generation.
"""

import json
import os
import pickle
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from intellicrack.utils.logger import logger

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    import torch.nn.functional as F
    from torch.utils.data import Dataset, DataLoader
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.debug("PyTorch not available, neural fuzzing will use fallback implementations")

try:
    from ...ai.predictive_intelligence import PredictiveIntelligence
    from ...ai.llm_backends import LLMBackends
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False


class NetworkArchitecture(Enum):
    """Neural network architectures for fuzzing."""
    FEEDFORWARD = "feedforward"
    LSTM = "lstm"
    GRU = "gru"
    TRANSFORMER = "transformer"
    VARIATIONAL_AUTOENCODER = "vae"
    GENERATIVE_ADVERSARIAL = "gan"


class TrainingStrategy(Enum):
    """Training strategies for neural fuzzing."""
    SUPERVISED = "supervised"
    UNSUPERVISED = "unsupervised"
    REINFORCEMENT = "reinforcement"
    ADVERSARIAL = "adversarial"
    SEMI_SUPERVISED = "semi_supervised"


@dataclass
class TrainingMetrics:
    """Training metrics for neural models."""
    epoch: int
    loss: float
    accuracy: float
    generation_quality: float
    convergence_rate: float
    training_time: float


@dataclass
class NeuralGenerationResult:
    """Result from neural generation."""
    data: bytes
    confidence: float
    latent_vector: Optional[np.ndarray] = None
    generation_path: List[str] = field(default_factory=list)
    model_architecture: Optional[NetworkArchitecture] = None
    diversity_score: float = 0.0


class FuzzingDataset(Dataset):
    """Dataset for training neural fuzzing models."""
    
    def __init__(self, samples: List[bytes], labels: Optional[List[int]] = None,
                 sequence_length: int = 256):
        self.samples = samples
        self.labels = labels or [0] * len(samples)
        self.sequence_length = sequence_length
        
    def __len__(self):
        return len(self.samples)
        
    def __getitem__(self, idx):
        sample = self.samples[idx]
        label = self.labels[idx]
        
        # Convert bytes to sequence
        if len(sample) > self.sequence_length:
            sample = sample[:self.sequence_length]
        else:
            sample = sample + b'\x00' * (self.sequence_length - len(sample))
            
        # Convert to tensor
        sequence = torch.tensor([b for b in sample], dtype=torch.float32) / 255.0
        
        return sequence, torch.tensor(label, dtype=torch.long)


class NeuralNetworkBase(nn.Module, ABC):
    """Base class for neural fuzzing networks."""
    
    def __init__(self, input_size: int, output_size: int):
        super().__init__()
        self.input_size = input_size
        self.output_size = output_size
        self.architecture = NetworkArchitecture.FEEDFORWARD
        
    @abstractmethod
    def forward(self, x):
        """Forward pass."""
        pass
        
    @abstractmethod
    def generate(self, seed: Optional[torch.Tensor] = None, length: int = 256) -> torch.Tensor:
        """Generate new input."""
        pass


class FeedforwardGenerator(NeuralNetworkBase):
    """Feedforward neural network for input generation."""
    
    def __init__(self, input_size: int = 256, hidden_size: int = 512, output_size: int = 256):
        super().__init__(input_size, output_size)
        self.architecture = NetworkArchitecture.FEEDFORWARD
        
        self.layers = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size, hidden_size * 2),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size * 2, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, output_size),
            nn.Sigmoid()
        )
        
    def forward(self, x):
        return self.layers(x)
        
    def generate(self, seed: Optional[torch.Tensor] = None, length: int = 256) -> torch.Tensor:
        """Generate new input using random seed."""
        if seed is None:
            seed = torch.randn(1, self.input_size)
        return self.forward(seed)


class LSTMGenerator(NeuralNetworkBase):
    """LSTM-based sequence generator for fuzzing."""
    
    def __init__(self, vocab_size: int = 256, embed_size: int = 128, 
                 hidden_size: int = 256, num_layers: int = 2):
        super().__init__(vocab_size, vocab_size)
        self.architecture = NetworkArchitecture.LSTM
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        self.embedding = nn.Embedding(vocab_size, embed_size)
        self.lstm = nn.LSTM(embed_size, hidden_size, num_layers, batch_first=True, dropout=0.2)
        self.output_layer = nn.Linear(hidden_size, vocab_size)
        
    def forward(self, x, hidden=None):
        embedded = self.embedding(x.long())
        output, hidden = self.lstm(embedded, hidden)
        output = self.output_layer(output)
        return output, hidden
        
    def generate(self, seed: Optional[torch.Tensor] = None, length: int = 256) -> torch.Tensor:
        """Generate sequence using LSTM."""
        if seed is None:
            # Start with random byte
            current_input = torch.randint(0, 256, (1, 1))
        else:
            current_input = seed[:, :1].long()
            
        generated = []
        hidden = None
        
        with torch.no_grad():
            for _ in range(length):
                output, hidden = self.forward(current_input, hidden)
                
                # Sample next byte
                probs = F.softmax(output[:, -1, :], dim=-1)
                next_byte = torch.multinomial(probs, 1)
                generated.append(next_byte.item())
                
                current_input = next_byte.unsqueeze(0)
                
        return torch.tensor(generated, dtype=torch.float32)


class VariationalAutoencoder(NeuralNetworkBase):
    """Variational Autoencoder for input generation."""
    
    def __init__(self, input_size: int = 256, latent_size: int = 64, hidden_size: int = 512):
        super().__init__(input_size, input_size)
        self.architecture = NetworkArchitecture.VARIATIONAL_AUTOENCODER
        self.latent_size = latent_size
        
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU()
        )
        
        self.mu_layer = nn.Linear(hidden_size // 2, latent_size)
        self.logvar_layer = nn.Linear(hidden_size // 2, latent_size)
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_size, hidden_size // 2),
            nn.ReLU(),
            nn.Linear(hidden_size // 2, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, input_size),
            nn.Sigmoid()
        )
        
    def encode(self, x):
        """Encode input to latent space."""
        h = self.encoder(x)
        mu = self.mu_layer(h)
        logvar = self.logvar_layer(h)
        return mu, logvar
        
    def reparameterize(self, mu, logvar):
        """Reparameterization trick."""
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std
        
    def decode(self, z):
        """Decode from latent space."""
        return self.decoder(z)
        
    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        return self.decode(z), mu, logvar
        
    def generate(self, seed: Optional[torch.Tensor] = None, length: int = 256) -> torch.Tensor:
        """Generate new input from latent space."""
        if seed is None:
            z = torch.randn(1, self.latent_size)
        else:
            # Use seed to generate latent vector
            mu, logvar = self.encode(seed)
            z = self.reparameterize(mu, logvar)
            
        return self.decode(z)


class GenerativeAdversarialNetwork:
    """Generative Adversarial Network for fuzzing input generation."""
    
    def __init__(self, input_size: int = 256, latent_size: int = 100):
        self.input_size = input_size
        self.latent_size = latent_size
        
        # Generator
        self.generator = nn.Sequential(
            nn.Linear(latent_size, 256),
            nn.ReLU(),
            nn.Linear(256, 512),
            nn.ReLU(),
            nn.Linear(512, 1024),
            nn.ReLU(),
            nn.Linear(1024, input_size),
            nn.Tanh()
        )
        
        # Discriminator
        self.discriminator = nn.Sequential(
            nn.Linear(input_size, 1024),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            nn.Linear(1024, 512),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.3),
            nn.Linear(256, 1),
            nn.Sigmoid()
        )
        
    def generate(self, num_samples: int = 1) -> torch.Tensor:
        """Generate samples using generator."""
        z = torch.randn(num_samples, self.latent_size)
        return self.generator(z)


class NeuralFuzzer:
    """Neural network-based fuzzer with multiple architectures."""
    
    def __init__(self, architecture: NetworkArchitecture = NetworkArchitecture.LSTM):
        self.logger = logger.getChild("NeuralFuzzer")
        self.architecture = architecture
        self.model = None
        self.optimizer = None
        self.criterion = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu") if TORCH_AVAILABLE else None
        
        # Training state
        self.training_metrics = []
        self.is_trained = False
        self.training_data = []
        
        # Generation parameters
        self.temperature = 1.0
        self.diversity_penalty = 0.1
        
        # Fallback for when PyTorch is not available
        self.fallback_patterns = [
            b"\x00" * 32,
            b"\xFF" * 32,
            b"\x41" * 32,
            b"\x90" * 32,
            b"AAAA" * 8,
            b"1234" * 8
        ]
        
        if TORCH_AVAILABLE:
            self._initialize_model()
        else:
            self.logger.warning("PyTorch not available, using fallback pattern generation")
            
    def _initialize_model(self):
        """Initialize neural network model."""
        if not TORCH_AVAILABLE:
            return
            
        try:
            if self.architecture == NetworkArchitecture.FEEDFORWARD:
                self.model = FeedforwardGenerator()
            elif self.architecture == NetworkArchitecture.LSTM:
                self.model = LSTMGenerator()
            elif self.architecture == NetworkArchitecture.VARIATIONAL_AUTOENCODER:
                self.model = VariationalAutoencoder()
            elif self.architecture == NetworkArchitecture.GENERATIVE_ADVERSARIAL:
                self.model = GenerativeAdversarialNetwork()
            else:
                self.model = LSTMGenerator()  # Default fallback
                
            if hasattr(self.model, 'to'):
                self.model = self.model.to(self.device)
                
            # Initialize optimizer and loss
            if hasattr(self.model, 'parameters'):
                self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)
                self.criterion = nn.CrossEntropyLoss()
                
            self.logger.info(f"Initialized {self.architecture.value} model on {self.device}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize model: {e}")
            self.model = None
            
    def add_training_sample(self, data: bytes, label: int = 0):
        """Add training sample to dataset."""
        self.training_data.append({
            "data": data,
            "label": label,
            "timestamp": time.time()
        })
        
        # Limit training data size
        if len(self.training_data) > 10000:
            self.training_data = self.training_data[-5000:]
            
        self.logger.debug(f"Added training sample ({len(data)} bytes, label={label})")
        
    def train_model(self, epochs: int = 100, batch_size: int = 32) -> List[TrainingMetrics]:
        """Train the neural network model."""
        if not TORCH_AVAILABLE or not self.model:
            self.logger.warning("Cannot train: PyTorch or model not available")
            return []
            
        if len(self.training_data) < 10:
            self.logger.warning("Insufficient training data")
            return []
            
        try:
            # Prepare dataset
            samples = [item["data"] for item in self.training_data]
            labels = [item["label"] for item in self.training_data]
            
            dataset = FuzzingDataset(samples, labels)
            dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
            
            metrics = []
            
            for epoch in range(epochs):
                epoch_loss = 0.0
                correct_predictions = 0
                total_predictions = 0
                start_time = time.time()
                
                for batch_inputs, batch_labels in dataloader:
                    if hasattr(self.model, 'to'):
                        batch_inputs = batch_inputs.to(self.device)
                        batch_labels = batch_labels.to(self.device)
                    
                    self.optimizer.zero_grad()
                    
                    # Forward pass depends on model type
                    if self.architecture == NetworkArchitecture.VARIATIONAL_AUTOENCODER:
                        outputs, mu, logvar = self.model(batch_inputs)
                        # VAE loss
                        recon_loss = F.mse_loss(outputs, batch_inputs)
                        kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
                        loss = recon_loss + 0.1 * kl_loss
                    elif self.architecture == NetworkArchitecture.LSTM:
                        outputs, _ = self.model(batch_inputs.unsqueeze(-1))
                        # Shift targets for next-token prediction
                        targets = batch_inputs[:, 1:].long()
                        outputs = outputs[:, :-1, :]
                        loss = self.criterion(outputs.reshape(-1, outputs.size(-1)), targets.reshape(-1))
                    else:
                        outputs = self.model(batch_inputs)
                        loss = F.mse_loss(outputs, batch_inputs)
                    
                    loss.backward()
                    self.optimizer.step()
                    
                    epoch_loss += loss.item()
                    total_predictions += batch_inputs.size(0)
                
                # Calculate metrics
                avg_loss = epoch_loss / len(dataloader)
                training_time = time.time() - start_time
                
                # Generate sample to assess quality
                quality_score = self._assess_generation_quality()
                
                epoch_metrics = TrainingMetrics(
                    epoch=epoch,
                    loss=avg_loss,
                    accuracy=quality_score,  # Use quality score as accuracy proxy
                    generation_quality=quality_score,
                    convergence_rate=0.0,
                    training_time=training_time
                )
                
                metrics.append(epoch_metrics)
                self.training_metrics.append(epoch_metrics)
                
                if epoch % 10 == 0:
                    self.logger.info(f"Epoch {epoch}/{epochs}: Loss={avg_loss:.4f}, "
                                   f"Quality={quality_score:.3f}")
                    
            self.is_trained = True
            self.logger.info(f"Training completed: {epochs} epochs")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Training failed: {e}")
            return []
            
    def generate_input(self, target_size: int = 256, 
                      seed: Optional[bytes] = None,
                      diversity: float = 0.5) -> NeuralGenerationResult:
        """Generate fuzzing input using neural network."""
        if not TORCH_AVAILABLE or not self.model:
            return self._fallback_generation(target_size)
            
        try:
            with torch.no_grad():
                # Prepare seed
                seed_tensor = None
                if seed:
                    seed_array = np.array([b for b in seed[:target_size]])
                    if len(seed_array) < target_size:
                        seed_array = np.pad(seed_array, (0, target_size - len(seed_array)))
                    seed_tensor = torch.tensor(seed_array, dtype=torch.float32).unsqueeze(0) / 255.0
                    if hasattr(self.model, 'to'):
                        seed_tensor = seed_tensor.to(self.device)
                
                # Generate
                if hasattr(self.model, 'generate'):
                    output = self.model.generate(seed_tensor, target_size)
                else:
                    # GAN case
                    output = self.model.generate(1)
                    
                # Convert to bytes
                if output.dim() > 1:
                    output = output.flatten()
                    
                output_array = (output.cpu().numpy() * 255).astype(np.uint8)
                
                # Apply diversity
                if diversity > 0:
                    noise = np.random.normal(0, diversity * 50, output_array.shape)
                    output_array = np.clip(output_array + noise, 0, 255).astype(np.uint8)
                
                # Ensure target size
                if len(output_array) > target_size:
                    output_array = output_array[:target_size]
                elif len(output_array) < target_size:
                    padding = np.random.randint(0, 256, target_size - len(output_array), dtype=np.uint8)
                    output_array = np.concatenate([output_array, padding])
                
                data = bytes(output_array)
                
                # Calculate confidence
                confidence = 0.8 if self.is_trained else 0.3
                if seed:
                    confidence += 0.1  # Slightly higher if seeded
                    
                return NeuralGenerationResult(
                    data=data,
                    confidence=confidence,
                    latent_vector=seed_tensor.cpu().numpy() if seed_tensor is not None else None,
                    generation_path=[f"{self.architecture.value}_generation"],
                    model_architecture=self.architecture,
                    diversity_score=diversity
                )
                
        except Exception as e:
            self.logger.debug(f"Neural generation failed: {e}")
            return self._fallback_generation(target_size)
            
    def _fallback_generation(self, target_size: int) -> NeuralGenerationResult:
        """Fallback generation when neural network is not available."""
        # Use pattern-based generation
        base_pattern = random.choice(self.fallback_patterns)
        
        # Repeat pattern to fill target size
        repeat_count = (target_size + len(base_pattern) - 1) // len(base_pattern)
        data = (base_pattern * repeat_count)[:target_size]
        
        # Add some randomness
        data = bytearray(data)
        for i in range(min(10, len(data))):
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
            
        return NeuralGenerationResult(
            data=bytes(data),
            confidence=0.2,  # Low confidence for fallback
            generation_path=["fallback_pattern"],
            diversity_score=0.3
        )
        
    def _assess_generation_quality(self) -> float:
        """Assess quality of generated samples."""
        if not hasattr(self.model, 'generate'):
            return 0.0
            
        try:
            # Generate small sample
            sample = self.model.generate(length=64)
            
            # Calculate entropy as quality metric
            if isinstance(sample, torch.Tensor):
                sample_bytes = (sample.cpu().numpy() * 255).astype(np.uint8)
            else:
                sample_bytes = sample
                
            # Calculate byte frequency entropy
            frequencies = np.bincount(sample_bytes, minlength=256)
            frequencies = frequencies / frequencies.sum()
            entropy = -np.sum(frequencies * np.log2(frequencies + 1e-10))
            
            # Normalize to 0-1 range (max entropy for uniform distribution is 8)
            quality = entropy / 8.0
            
            return min(1.0, quality)
            
        except Exception:
            return 0.0
            
    def generate_batch(self, count: int, target_size: int = 256, 
                      diversity_range: Tuple[float, float] = (0.3, 0.8)) -> List[NeuralGenerationResult]:
        """Generate batch of inputs with varying diversity."""
        results = []
        
        for i in range(count):
            diversity = random.uniform(diversity_range[0], diversity_range[1])
            
            # Occasionally use previous generation as seed
            seed = None
            if results and random.random() < 0.3:
                seed = results[-1].data[:target_size//2]
                
            result = self.generate_input(target_size, seed, diversity)
            results.append(result)
            
        self.logger.info(f"Generated {len(results)} neural fuzzing inputs")
        return results
        
    def evolve_inputs(self, parent_inputs: List[bytes], generations: int = 5) -> List[NeuralGenerationResult]:
        """Evolve inputs through multiple generations."""
        current_generation = parent_inputs
        results = []
        
        for gen in range(generations):
            next_generation = []
            
            for parent in current_generation:
                # Generate offspring using parent as seed
                offspring = self.generate_input(len(parent), parent, diversity=0.4)
                results.append(offspring)
                next_generation.append(offspring.data)
                
                # Add mutation
                mutated = self._mutate_input(offspring.data)
                if mutated:
                    mutated_result = NeuralGenerationResult(
                        data=mutated,
                        confidence=offspring.confidence * 0.9,
                        generation_path=offspring.generation_path + [f"mutation_gen_{gen}"],
                        model_architecture=self.architecture,
                        diversity_score=offspring.diversity_score + 0.1
                    )
                    results.append(mutated_result)
                    next_generation.append(mutated)
                    
            # Select best candidates for next generation
            current_generation = next_generation[:len(parent_inputs)]
            
        self.logger.info(f"Evolved inputs through {generations} generations")
        return results
        
    def _mutate_input(self, data: bytes) -> Optional[bytes]:
        """Apply neural-inspired mutations."""
        if not data:
            return None
            
        data = bytearray(data)
        mutation_count = random.randint(1, 3)
        
        for _ in range(mutation_count):
            mutation_type = random.choice([
                "gradient_noise", "activation_shift", "weight_decay", "dropout"
            ])
            
            if mutation_type == "gradient_noise":
                # Add gaussian noise
                pos = random.randint(0, len(data) - 1)
                noise = int(random.gauss(0, 20))
                data[pos] = max(0, min(255, data[pos] + noise))
                
            elif mutation_type == "activation_shift":
                # Shift values like ReLU activation
                pos = random.randint(0, len(data) - 1)
                if data[pos] < 128:
                    data[pos] = 0  # ReLU cutoff
                else:
                    data[pos] = min(255, data[pos] + random.randint(10, 50))
                    
            elif mutation_type == "weight_decay":
                # Gradual value decay
                start = random.randint(0, len(data) - 5)
                for i in range(5):
                    if start + i < len(data):
                        data[start + i] = int(data[start + i] * 0.9)
                        
            elif mutation_type == "dropout":
                # Random dropout (set to zero)
                positions = random.sample(range(len(data)), k=min(5, len(data)))
                for pos in positions:
                    data[pos] = 0
                    
        return bytes(data)
        
    def save_model(self, filepath: str):
        """Save trained model to file."""
        if not TORCH_AVAILABLE or not self.model:
            self.logger.warning("Cannot save: model not available")
            return
            
        try:
            model_data = {
                "architecture": self.architecture.value,
                "state_dict": self.model.state_dict() if hasattr(self.model, 'state_dict') else None,
                "training_metrics": self.training_metrics,
                "is_trained": self.is_trained,
                "device": str(self.device)
            }
            
            torch.save(model_data, filepath)
            self.logger.info(f"Model saved to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to save model: {e}")
            
    def load_model(self, filepath: str):
        """Load trained model from file."""
        if not TORCH_AVAILABLE:
            self.logger.warning("Cannot load: PyTorch not available")
            return
            
        try:
            model_data = torch.load(filepath, map_location=self.device)
            
            self.architecture = NetworkArchitecture(model_data["architecture"])
            self.training_metrics = model_data.get("training_metrics", [])
            self.is_trained = model_data.get("is_trained", False)
            
            # Reinitialize model with loaded architecture
            self._initialize_model()
            
            if model_data["state_dict"] and hasattr(self.model, 'load_state_dict'):
                self.model.load_state_dict(model_data["state_dict"])
                
            self.logger.info(f"Model loaded from {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        info = {
            "architecture": self.architecture.value,
            "is_trained": self.is_trained,
            "training_samples": len(self.training_data),
            "pytorch_available": TORCH_AVAILABLE,
            "device": str(self.device) if self.device else "none"
        }
        
        if self.model and hasattr(self.model, 'parameters'):
            total_params = sum(p.numel() for p in self.model.parameters())
            info["total_parameters"] = total_params
            info["trainable_parameters"] = sum(p.numel() for p in self.model.parameters() if p.requires_grad)
            
        if self.training_metrics:
            latest_metrics = self.training_metrics[-1]
            info["latest_loss"] = latest_metrics.loss
            info["latest_quality"] = latest_metrics.generation_quality
            
        return info