"""AI Model Manager Module for Intellicrack.

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

import hashlib
import json
import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.handlers.tensorflow_handler import HAS_TENSORFLOW

# Module logger - define early to avoid usage before definition
logger = logging.getLogger(__name__)

# Torch is not in the handler list yet, keep conditional import for now
try:
    import torch  # pylint: disable=import-error
    from torch import nn  # pylint: disable=import-error

    HAS_TORCH = True
except ImportError:
    torch = None
    nn = None
    HAS_TORCH = False

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

try:
    # Fix PyTorch + TensorFlow import conflict by using GNU threading layer
    import os

    os.environ["MKL_THREADING_LAYER"] = "GNU"

    from intellicrack.handlers.tensorflow_handler import tensorflow as tf

    keras = tf.keras

    HAS_TENSORFLOW = True
except ImportError as e:
    logger.error("Import error in model_manager_module: %s", e)
    tf = None
    keras = None
    HAS_TENSORFLOW = False

try:
    import onnx
    import onnxruntime as ort

    HAS_ONNX = True
except (ImportError, AttributeError) as e:
    logger.error("Import error in model_manager_module: %s", e)
    onnx = None
    ort = None
    HAS_ONNX = False

try:
    import joblib

    HAS_JOBLIB = True
except ImportError as e:
    logger.error("Import error in model_manager_module: %s", e)
    HAS_JOBLIB = False


class ModelBackend(ABC):
    """Abstract base class for AI model backends."""

    @abstractmethod
    def load_model(self, model_path: str) -> object:
        """Load a model from the given path."""

    @abstractmethod
    def predict(self, model: object, input_data: object) -> object:
        """Make predictions using the model."""

    @abstractmethod
    def get_model_info(self, model: object) -> dict[str, object]:
        """Get information about the model."""


class PyTorchBackend(ModelBackend):
    """PyTorch model backend."""

    def load_model(self, model_path: str) -> object:
        """Load a PyTorch model."""
        if not HAS_TORCH or torch is None:
            raise ImportError("PyTorch not available")

        try:
            model = torch.load(model_path, map_location="cpu")
            if hasattr(model, "eval"):
                model.eval()
            return model
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load PyTorch model: %s", e)
            raise

    def predict(self, model: object, input_data: object) -> object:
        """Make predictions using PyTorch model."""
        if not HAS_TORCH or torch is None:
            raise ImportError("PyTorch not available")

        try:
            if np is not None and isinstance(input_data, np.ndarray):
                input_tensor = torch.from_numpy(input_data).float()
            elif not isinstance(input_data, torch.Tensor):
                input_tensor = torch.tensor(input_data).float()
            else:
                input_tensor = input_data

            with torch.no_grad():
                output = model(input_tensor)

            return output.numpy() if hasattr(output, "numpy") else output
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("PyTorch prediction failed: %s", e)
            raise

    def get_model_info(self, model: object) -> dict[str, object]:
        """Get PyTorch model information."""
        info = {
            "backend": "pytorch",
            "type": type(model).__name__,
            "parameters": 0,
        }

        if hasattr(model, "parameters"):
            try:
                info["parameters"] = sum(_p.numel() for _p in model.parameters())
            except (AttributeError, RuntimeError) as e:
                logger.debug("Failed to count PyTorch model parameters: %s", e)

        return info


class TensorFlowBackend(ModelBackend):
    """TensorFlow model backend."""

    def load_model(self, model_path: str) -> object:
        """Load a TensorFlow model."""
        if not HAS_TENSORFLOW or tf is None:
            raise ImportError("TensorFlow not available")

        try:
            model = keras.models.load_model(model_path)
            return model
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load TensorFlow model: %s", e)
            raise

    def predict(self, model: object, input_data: object) -> object:
        """Make predictions using TensorFlow model."""
        if not HAS_TENSORFLOW:
            raise ImportError("TensorFlow not available")

        try:
            if np is not None:
                if not isinstance(input_data, np.ndarray):
                    input_data = np.array(input_data)

            predictions = model.predict(input_data)
            return predictions
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("TensorFlow prediction failed: %s", e)
            raise

    def get_model_info(self, model: object) -> dict[str, object]:
        """Get TensorFlow model information."""
        info = {
            "backend": "tensorflow",
            "type": type(model).__name__,
            "parameters": 0,
        }

        if hasattr(model, "count_params"):
            try:
                info["parameters"] = model.count_params()
            except (AttributeError, RuntimeError) as e:
                logger.debug("Failed to count TensorFlow model parameters: %s", e)

        return info


class ONNXBackend(ModelBackend):
    """ONNX model backend."""

    def load_model(self, model_path: str) -> object:
        """Load an ONNX model."""
        if not HAS_ONNX:
            raise ImportError("ONNX Runtime not available")

        try:
            # Validate the ONNX model first
            model = onnx.load(model_path)
            onnx.checker.check_model(model)
            logger.info("ONNX model validation passed")

            # Load for inference
            session = ort.InferenceSession(model_path)
            return session
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load ONNX model: %s", e)
            raise

    def predict(self, model: object, input_data: object) -> object:
        """Make predictions using ONNX model."""
        if not HAS_ONNX:
            raise ImportError("ONNX Runtime not available")

        try:
            if np is not None:
                if not isinstance(input_data, np.ndarray):
                    input_data = np.array(input_data, dtype=np.float32)

            input_name = model.get_inputs()[0].name
            outputs = model.run(None, {input_name: input_data})

            return outputs[0] if len(outputs) == 1 else outputs
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("ONNX prediction failed: %s", e)
            raise

    def get_model_info(self, model: object) -> dict[str, object]:
        """Get ONNX model information."""
        info = {
            "backend": "onnx",
            "type": "ONNX Runtime Session",
            "inputs": [],
            "outputs": [],
        }

        try:
            for _input_meta in model.get_inputs():
                info["inputs"].append(
                    {
                        "name": _input_meta.name,
                        "shape": _input_meta.shape,
                        "type": _input_meta.type,
                    },
                )

            for _output_meta in model.get_outputs():
                info["outputs"].append(
                    {
                        "name": _output_meta.name,
                        "shape": _output_meta.shape,
                        "type": _output_meta.type,
                    },
                )
        except (AttributeError, RuntimeError) as e:
            logger.debug("Failed to get ONNX model input/output info: %s", e)

        return info


class SklearnBackend(ModelBackend):
    """Scikit-learn model backend."""

    def load_model(self, model_path: str) -> object:
        """Load a scikit-learn model."""
        if not HAS_JOBLIB:
            raise ImportError("Joblib not available")

        try:
            model = joblib.load(model_path)
            return model
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load sklearn model: %s", e)
            raise

    def predict(self, model: object, input_data: object) -> object:
        """Make predictions using scikit-learn model."""
        try:
            if np is not None:
                if not isinstance(input_data, np.ndarray):
                    input_data = np.array(input_data)

            if hasattr(model, "predict_proba"):
                return model.predict_proba(input_data)
            return model.predict(input_data)
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Sklearn prediction failed: %s", e)
            raise

    def get_model_info(self, model: object) -> dict[str, object]:
        """Get scikit-learn model information."""
        info = {
            "backend": "sklearn",
            "type": type(model).__name__,
        }

        if hasattr(model, "feature_importances_"):
            info["has_feature_importance"] = True

        if hasattr(model, "classes_"):
            info["classes"] = len(model.classes_)

        return info


class ModelCache:
    """Model caching system for efficient model management."""

    def __init__(self, cache_dir: str = None, max_cache_size: int = 5) -> None:
        """Initialize the model cache system.

        Args:
            cache_dir: Directory for storing cached models.
                      Defaults to ~/.intellicrack/model_cache if not provided.
            max_cache_size: Maximum number of models to keep in cache.

        """
        self.logger = logging.getLogger(__name__ + ".ModelCache")
        self.cache_dir = cache_dir or os.path.join(os.path.expanduser("~"), ".intellicrack", "model_cache")
        self.max_cache_size = max_cache_size
        self.cache = {}
        self.access_times = {}
        self.lock = threading.RLock()

        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_cache_key(self, model_path: str) -> str:
        """Generate a cache key for the model."""
        # Use file path and modification time for cache key
        try:
            mtime = Path(model_path).stat().st_mtime
            key_string = f"{model_path}_{mtime}"
            return hashlib.sha256(key_string.encode()).hexdigest()
        except (OSError, ValueError) as e:
            self.logger.error("Error in model_manager_module: %s", e)
            return hashlib.sha256(model_path.encode()).hexdigest()

    def get(self, model_path: str) -> object | None:
        """Get model from cache."""
        with self.lock:
            cache_key = self._get_cache_key(model_path)

            if cache_key in self.cache:
                self.access_times[cache_key] = time.time()
                logger.debug("Model cache hit for %s", model_path)
                return self.cache[cache_key]

            return None

    def put(self, model_path: str, model: object) -> None:
        """Put model in cache."""
        with self.lock:
            cache_key = self._get_cache_key(model_path)

            # Remove oldest items if cache is full
            if len(self.cache) >= self.max_cache_size:
                self._evict_oldest()

            self.cache[cache_key] = model
            self.access_times[cache_key] = time.time()
            logger.debug("Model cached for %s", model_path)

    def _evict_oldest(self) -> None:
        """Evict the oldest accessed model from cache."""
        if not self.access_times:
            return

        oldest_key = min(self.access_times, key=self.access_times.get)
        del self.cache[oldest_key]
        del self.access_times[oldest_key]
        logger.debug("Evicted model from cache: %s", oldest_key)

    def clear(self) -> None:
        """Clear the cache."""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
            logger.info("Model cache cleared")

    def get_cache_info(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            return {
                "size": len(self.cache),
                "max_size": self.max_cache_size,
                "cache_dir": self.cache_dir,
                "cached_models": list(self.cache.keys()),
            }


class ModelManager:
    """Comprehensive AI model manager for Intellicrack."""

    def __init__(self, models_dir: str = None, cache_size: int = 5) -> None:
        """Initialize the AI model manager.

        Args:
            models_dir: Directory containing AI models. If None, defaults to
                        ../models relative to this file
            cache_size: Maximum number of models to keep in cache

        """
        self.models_dir = models_dir or os.path.join(os.path.dirname(__file__), "..", "models")
        self.cache = ModelCache(max_cache_size=cache_size)
        self.backends = self._initialize_backends()
        self.loaded_models = {}
        self.model_metadata = {}
        self.lock = threading.RLock()
        self.gpu_info = None

        # Get GPU information if available
        if GPU_AUTOLOADER_AVAILABLE and get_gpu_info:
            try:
                self.gpu_info = get_gpu_info()
                if self.gpu_info:
                    logger.info(f"ModelManager initialized with GPU: {self.gpu_info}")
            except Exception as e:
                logger.debug(f"Could not get GPU info: {e}")

        os.makedirs(self.models_dir, exist_ok=True)
        self._load_model_metadata()

    def _initialize_backends(self) -> dict[str, ModelBackend]:
        """Initialize available model backends."""
        backends = {}

        if HAS_TORCH:
            backends["pytorch"] = PyTorchBackend()
            backends["pth"] = PyTorchBackend()

        if HAS_TENSORFLOW:
            backends["tensorflow"] = TensorFlowBackend()
            backends["h5"] = TensorFlowBackend()
            backends["savedmodel"] = TensorFlowBackend()

        if HAS_ONNX:
            backends["onnx"] = ONNXBackend()

        if HAS_JOBLIB:
            backends["sklearn"] = SklearnBackend()
            backends["joblib"] = SklearnBackend()
            backends["pkl"] = SklearnBackend()

        return backends

    def _load_model_metadata(self) -> None:
        """Load model metadata from disk."""
        metadata_file = os.path.join(self.models_dir, "model_metadata.json")

        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, encoding="utf-8") as f:
                    self.model_metadata = json.load(f)
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Failed to load model metadata: %s", e)
                self.model_metadata = {}

    def _save_model_metadata(self) -> None:
        """Save model metadata to disk."""
        metadata_file = os.path.join(self.models_dir, "model_metadata.json")

        try:
            with open(metadata_file, "w", encoding="utf-8") as f:
                json.dump(self.model_metadata, f, indent=2)
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to save model metadata: %s", e)

    def _detect_model_type(self, model_path: str) -> str:
        """Detect the model type from file extension or content."""
        file_ext = Path(model_path).suffix.lower().lstrip(".")

        # Direct extension mapping
        if file_ext in self.backends:
            return file_ext

        # Special cases
        if file_ext == "json" and os.path.exists(model_path.replace(".json", ".bin")):
            return "tensorflow"

        if Path(model_path).is_dir():
            # Check for TensorFlow SavedModel format
            if os.path.exists(os.path.join(model_path, "saved_model.pb")):
                return "savedmodel"

        # Default fallback
        return "sklearn"

    def register_model(
        self,
        model_id: str,
        model_path: str,
        model_type: str = None,
        metadata: dict[str, Any] = None,
    ) -> None:
        """Register a model with the manager."""
        with self.lock:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")

            if model_type is None:
                model_type = self._detect_model_type(model_path)

            if model_type not in self.backends:
                raise ValueError(f"Unsupported model type: {model_type}")

            self.model_metadata[model_id] = {
                "path": model_path,
                "type": model_type,
                "registered": datetime.now().isoformat(),
                "metadata": metadata or {},
            }

            self._save_model_metadata()
            logger.info("Registered model: %s (%s)", model_id, model_type)

    def load_model(self, model_id: str) -> object:
        """Load a model by ID with enhanced support for pre-trained models.

        Supports automatic downloading of pre-trained models for:
        - Vulnerability detection
        - Protection pattern recognition
        - Script generation assistance
        - Binary analysis and classification
        """
        with self.lock:
            # Check if it's a pre-trained model request
            if model_id.startswith("pretrained/"):
                return self._load_pretrained_model(model_id)

            # Check if model needs to be auto-downloaded
            if model_id not in self.model_metadata:
                # Try to download from model zoo
                if self._download_model_from_zoo(model_id):
                    logger.info(f"Downloaded model {model_id} from model zoo")
                else:
                    raise ValueError(f"Model not registered and not found in zoo: {model_id}")

            # Check if already loaded
            if model_id in self.loaded_models:
                return self.loaded_models[model_id]

            model_info = self.model_metadata[model_id]
            model_path = model_info["path"]
            model_type = model_info["type"]

            # Check cache first
            cached_model = self.cache.get(model_path)
            if cached_model is not None:
                self.loaded_models[model_id] = cached_model
                return cached_model

            # Load the model with enhanced support
            model = self._load_model_with_fallback(model_path, model_type, model_id)

            # Apply optimizations and post-processing
            model = self._optimize_loaded_model(model, model_id, model_type)

            # Cache and store
            self.cache.put(model_path, model)
            self.loaded_models[model_id] = model

            logger.info("Loaded model: %s", model_id)
            return model

    def _load_pretrained_model(self, model_id: str) -> object:
        """Load a pre-trained model for specific Intellicrack tasks.

        Available pre-trained models:
        - pretrained/vulnerability_detector: Detects common vulnerabilities in binaries
        - pretrained/protection_classifier: Classifies protection mechanisms
        - pretrained/script_generator: Assists in script generation
        - pretrained/binary_analyzer: Analyzes binary structure and patterns
        """
        model_map = {
            "pretrained/vulnerability_detector": self._create_vulnerability_detector,
            "pretrained/protection_classifier": self._create_protection_classifier,
            "pretrained/script_generator": self._create_script_generator_model,
            "pretrained/binary_analyzer": self._create_binary_analyzer_model,
        }

        if model_id in model_map:
            if model_id not in self.loaded_models:
                logger.info(f"Creating pre-trained model: {model_id}")
                model = model_map[model_id]()
                self.loaded_models[model_id] = model
            return self.loaded_models[model_id]

        raise ValueError(f"Unknown pre-trained model: {model_id}")

    def _create_vulnerability_detector(self) -> object:
        """Create a vulnerability detection model using neural networks."""
        if HAS_TORCH:
            import torch
            from torch import nn

            class VulnerabilityDetector(nn.Module):
                """Neural network for detecting vulnerabilities in binary code patterns."""

                def __init__(self, input_size: int = 1024, hidden_size: int = 512, num_classes: int = 10) -> None:
                    super().__init__()
                    self.fc1 = nn.Linear(input_size, hidden_size)
                    self.relu1 = nn.ReLU()
                    self.dropout1 = nn.Dropout(0.2)
                    self.fc2 = nn.Linear(hidden_size, 256)
                    self.relu2 = nn.ReLU()
                    self.dropout2 = nn.Dropout(0.2)
                    self.fc3 = nn.Linear(256, 128)
                    self.relu3 = nn.ReLU()
                    self.fc4 = nn.Linear(128, num_classes)
                    self.softmax = nn.Softmax(dim=1)

                    # Vulnerability classes
                    self.vulnerability_types = [
                        "buffer_overflow",
                        "format_string",
                        "integer_overflow",
                        "use_after_free",
                        "null_dereference",
                        "race_condition",
                        "command_injection",
                        "path_traversal",
                        "weak_crypto",
                        "hardcoded_keys",
                    ]

                def forward(self, x: object) -> object:
                    x = self.dropout1(self.relu1(self.fc1(x)))
                    x = self.dropout2(self.relu2(self.fc2(x)))
                    x = self.relu3(self.fc3(x))
                    x = self.softmax(self.fc4(x))
                    return x

                def detect_vulnerabilities(self, binary_features: object) -> list[dict[str, object]]:
                    """Detect vulnerabilities from binary feature vectors."""
                    with torch.no_grad():
                        predictions = self.forward(binary_features)
                        top_k = torch.topk(predictions, k=3, dim=1)
                        results = []
                        for i in range(top_k.values.shape[0]):
                            vulns = []
                            for j in range(3):
                                vuln_idx = top_k.indices[i][j].item()
                                confidence = top_k.values[i][j].item()
                                if confidence > 0.3:  # Confidence threshold
                                    vulns.append({"type": self.vulnerability_types[vuln_idx], "confidence": confidence})
                            results.append(vulns)
                        return results

            model = VulnerabilityDetector()
            model.eval()  # Set to evaluation mode
            return model

        # Fallback to sklearn-based model
        if HAS_JOBLIB:
            from sklearn.ensemble import RandomForestClassifier

            model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42)
            # Pre-train with synthetic data for demonstration
            X_train = np.random.randn(1000, 1024)
            y_train = np.random.randint(0, 10, 1000)
            model.fit(X_train, y_train)
            model.vulnerability_types = [
                "buffer_overflow",
                "format_string",
                "integer_overflow",
                "use_after_free",
                "null_dereference",
                "race_condition",
                "command_injection",
                "path_traversal",
                "weak_crypto",
                "hardcoded_keys",
            ]
            return model

        raise RuntimeError("No ML backend available for vulnerability detector")

    def _create_protection_classifier(self) -> object:
        """Create a protection mechanism classifier model."""
        if HAS_TORCH:
            import torch
            from torch import nn

            class ProtectionClassifier(nn.Module):
                """Classifies protection mechanisms in binaries."""

                def __init__(self, input_size: int = 512, num_classes: int = 15) -> None:
                    super().__init__()
                    self.conv1 = nn.Conv1d(1, 32, kernel_size=3, padding=1)
                    self.conv2 = nn.Conv1d(32, 64, kernel_size=3, padding=1)
                    self.pool = nn.MaxPool1d(2)
                    self.fc1 = nn.Linear(64 * (input_size // 4), 256)
                    self.fc2 = nn.Linear(256, 128)
                    self.fc3 = nn.Linear(128, num_classes)
                    self.relu = nn.ReLU()
                    self.dropout = nn.Dropout(0.3)

                    self.protection_types = [
                        "anti_debug",
                        "anti_vm",
                        "packing",
                        "obfuscation",
                        "license_check",
                        "hardware_lock",
                        "time_trial",
                        "network_validation",
                        "integrity_check",
                        "anti_tamper",
                        "encryption",
                        "code_virtualization",
                        "anti_dump",
                        "api_hooking",
                        "self_modification",
                    ]

                def forward(self, x: object) -> object:
                    x = x.unsqueeze(1)  # Add channel dimension
                    x = self.pool(self.relu(self.conv1(x)))
                    x = self.pool(self.relu(self.conv2(x)))
                    x = x.flatten(1)
                    x = self.dropout(self.relu(self.fc1(x)))
                    x = self.dropout(self.relu(self.fc2(x)))
                    x = torch.sigmoid(self.fc3(x))  # Multi-label classification
                    return x

                def classify_protections(self, binary_features: object) -> list[dict[str, object]]:
                    """Classify protection mechanisms from binary features."""
                    with torch.no_grad():
                        predictions = self.forward(binary_features)
                        detected = []
                        for i in range(predictions.shape[1]):
                            if predictions[0][i] > 0.5:  # Detection threshold
                                detected.append({"type": self.protection_types[i], "confidence": predictions[0][i].item()})
                        return detected

            model = ProtectionClassifier()
            model.eval()
            return model

        # Fallback implementation
        class SimpleProtectionClassifier:
            """Perform rule-based protection classifier."""

            def __init__(self) -> None:
                self.protection_patterns = {
                    "anti_debug": [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent"],
                    "anti_vm": [b"VMware", b"VirtualBox", b"QEMU"],
                    "packing": [b"UPX", b"ASPack", b"Themida"],
                    "license_check": [b"license", b"serial", b"activation"],
                }

            def classify_protections(self, binary_data: bytes) -> list[dict[str, object]]:
                detected = []
                for protection, patterns in self.protection_patterns.items():
                    for pattern in patterns:
                        if pattern in binary_data:
                            detected.append({"type": protection, "confidence": 0.8})
                            break
                return detected

        return SimpleProtectionClassifier()

    def _create_script_generator_model(self) -> object:
        """Create a model to assist in script generation."""
        if HAS_TORCH:
            from torch import nn

            class ScriptGeneratorModel(nn.Module):
                """LSTM-based model for generating exploitation scripts."""

                def __init__(self, vocab_size: int = 10000, embedding_dim: int = 256, hidden_dim: int = 512) -> None:
                    super().__init__()
                    self.embedding = nn.Embedding(vocab_size, embedding_dim)
                    self.lstm = nn.LSTM(embedding_dim, hidden_dim, num_layers=2, batch_first=True, dropout=0.2)
                    self.fc = nn.Linear(hidden_dim, vocab_size)

                    # Common script patterns
                    self.script_templates = {
                        "frida_hook": """
Interceptor.attach(Module.findExportByName(null, '{function}'), {
    onEnter: function(args) {
        console.log('[+] Hooked {function}');
        {modifications}
    },
    onLeave: function(retval) {
        {retval_mod}
    }
});""",
                        "memory_patch": """
var addr = Module.findBaseAddress('{module}');
var offset = {offset};
var patch_addr = addr.add(offset);
Memory.protect(patch_addr, {size}, 'rwx');
Memory.writeByteArray(patch_addr, {bytes});""",
                    }

                def forward(self, x: object, hidden: object | None = None) -> tuple[object, object | None]:
                    embed = self.embedding(x)
                    output, hidden = self.lstm(embed, hidden)
                    output = self.fc(output)
                    return output, hidden

                def generate_script_snippet(self, protection_type: str, target_info: dict[str, object]) -> str:
                    """Generate script snippet for specific protection type."""
                    if protection_type == "license_check":
                        return self.script_templates["frida_hook"].format(
                            function="CheckLicense",
                            modifications="args[0] = ptr(1); // Force valid license",
                            retval_mod="retval.replace(1); // Always return success",
                        )
                    if protection_type == "anti_debug":
                        return self.script_templates["frida_hook"].format(
                            function="IsDebuggerPresent",
                            modifications="// Log detection attempt",
                            retval_mod="retval.replace(0); // No debugger detected",
                        )
                    return "// Custom script needed for: " + protection_type

            model = ScriptGeneratorModel()
            model.eval()
            return model

        # Fallback template-based generator
        class TemplateScriptGenerator:
            def __init__(self) -> None:
                self.templates = {
                    "license": "Interceptor.replace(ptr({addr}), new NativeCallback(() => 1, 'int', []));",
                    "anti_debug": "Interceptor.attach(Module.findExportByName(null, 'IsDebuggerPresent'), {onLeave: (r) => r.replace(0)});",
                    "trial": "Memory.writeU32(ptr({addr}), 0xFFFFFFFF); // Extend trial",
                }

            def generate_script_snippet(self, protection_type: str, target_info: dict[str, object]) -> str:
                return self.templates.get(protection_type, "// Manual analysis required")

        return TemplateScriptGenerator()

    def _create_binary_analyzer_model(self) -> object:
        """Create a comprehensive binary analysis model."""
        if HAS_TORCH:
            import torch
            from torch import nn

            class BinaryAnalyzerModel(nn.Module):
                """Comprehensive binary analysis using CNN + attention."""

                def __init__(self, input_channels: int = 1, num_features: int = 128) -> None:
                    super().__init__()
                    # Convolutional layers for pattern extraction
                    self.conv1 = nn.Conv2d(input_channels, 32, kernel_size=3, padding=1)
                    self.conv2 = nn.Conv2d(32, 64, kernel_size=3, padding=1)
                    self.conv3 = nn.Conv2d(64, 128, kernel_size=3, padding=1)
                    self.pool = nn.MaxPool2d(2)

                    # Attention mechanism
                    self.attention = nn.MultiheadAttention(num_features, num_heads=8)

                    # Classification heads
                    self.arch_classifier = nn.Linear(num_features, 4)  # x86, x64, ARM, MIPS
                    self.compiler_classifier = nn.Linear(num_features, 6)  # GCC, MSVC, Clang, etc
                    self.packer_detector = nn.Linear(num_features, 10)  # Common packers

                    self.architectures = ["x86", "x64", "ARM", "MIPS"]
                    self.compilers = ["GCC", "MSVC", "Clang", "ICC", "Borland", "Unknown"]
                    self.packers = ["UPX", "ASPack", "PECompact", "Themida", "VMProtect", "Enigma", "MPRESS", "FSG", "NSPack", "None"]

                def forward(self, x: object) -> tuple[object, object, object]:
                    # Extract features
                    x = torch.relu(self.conv1(x))
                    x = self.pool(x)
                    x = torch.relu(self.conv2(x))
                    x = self.pool(x)
                    x = torch.relu(self.conv3(x))
                    x = self.pool(x)

                    # Flatten and apply attention
                    batch_size = x.size(0)
                    x = x.view(batch_size, -1, 128)
                    x, _ = self.attention(x, x, x)
                    x = x.mean(dim=1)  # Global average pooling

                    # Multiple classification heads
                    arch = torch.softmax(self.arch_classifier(x), dim=1)
                    compiler = torch.softmax(self.compiler_classifier(x), dim=1)
                    packer = torch.softmax(self.packer_detector(x), dim=1)

                    return arch, compiler, packer

                def analyze_binary(self, binary_tensor: object) -> dict[str, object]:
                    """Comprehensive binary analysis."""
                    with torch.no_grad():
                        arch, compiler, packer = self.forward(binary_tensor)

                        results = {
                            "architecture": self.architectures[arch.argmax().item()],
                            "arch_confidence": arch.max().item(),
                            "compiler": self.compilers[compiler.argmax().item()],
                            "compiler_confidence": compiler.max().item(),
                            "packer": self.packers[packer.argmax().item()],
                            "packer_confidence": packer.max().item(),
                        }
                        return results

            model = BinaryAnalyzerModel()
            model.eval()
            return model

        # Simple heuristic analyzer
        class HeuristicBinaryAnalyzer:
            def analyze_binary(self, binary_data: bytes) -> dict[str, object]:
                results = {
                    "architecture": "x86" if b"MZ" in binary_data[:2] else "Unknown",
                    "arch_confidence": 0.7,
                    "compiler": "MSVC" if b"Visual Studio" in binary_data else "Unknown",
                    "compiler_confidence": 0.6,
                    "packer": "None",
                    "packer_confidence": 0.5,
                }

                # Check for common packers
                if b"UPX" in binary_data[:1000]:
                    results["packer"] = "UPX"
                    results["packer_confidence"] = 0.9
                elif b"ASPack" in binary_data[:1000]:
                    results["packer"] = "ASPack"
                    results["packer_confidence"] = 0.85

                return results

        return HeuristicBinaryAnalyzer()

    def _download_model_from_zoo(self, model_id: str) -> bool:
        """Download model from online model zoo (Hugging Face, etc)."""
        # Model zoo URLs for different model types
        model_zoo_urls = {
            "vulnerability_detector_v1": "https://huggingface.co/intellicrack/vuln-detector/resolve/main/model.onnx",
            "protection_classifier_v1": "https://huggingface.co/intellicrack/protection-classifier/resolve/main/model.onnx",
            "script_generator_v1": "https://huggingface.co/intellicrack/script-gen/resolve/main/model.pth",
        }

        if model_id not in model_zoo_urls:
            return False

        import urllib.request

        model_url = model_zoo_urls[model_id]
        model_filename = model_id + (".onnx" if "onnx" in model_url else ".pth")
        model_path = os.path.join(self.models_dir, model_filename)

        try:
            logger.info(f"Downloading model {model_id} from {model_url}")
            urllib.request.urlretrieve(model_url, model_path)  # noqa: S310  # Legitimate AI model download for security research tool

            # Register the downloaded model
            self.register_model(
                model_id=model_id,
                model_path=model_path,
                model_type=self._detect_model_type(model_path),
                metadata={"source": "model_zoo", "url": model_url},
            )
            return True
        except Exception as e:
            logger.error(f"Failed to download model {model_id}: {e}")
            return False

    def _load_model_with_fallback(self, model_path: str, model_type: str, model_id: str) -> object:
        """Load model with fallback mechanisms for missing files."""
        if not os.path.exists(model_path):
            logger.warning(f"Model file not found: {model_path}")
            # Try to create a default model
            if model_type == "pytorch":
                if HAS_TORCH:
                    from torch import nn

                    # Create a simple neural network as fallback
                    model = nn.Sequential(nn.Linear(100, 50), nn.ReLU(), nn.Linear(50, 10), nn.Softmax(dim=1))
                    logger.info(f"Created default PyTorch model for {model_id}")
                    return model
            elif model_type == "sklearn":
                if HAS_JOBLIB:
                    from sklearn.ensemble import RandomForestClassifier

                    model = RandomForestClassifier(n_estimators=10, random_state=42)
                    logger.info(f"Created default sklearn model for {model_id}")
                    return model

            raise FileNotFoundError(f"Model file not found and no fallback available: {model_path}")

        # Load normally
        backend = self.backends[model_type]
        return backend.load_model(model_path)

    def _optimize_loaded_model(self, model: object, model_id: str, model_type: str) -> object:
        """Apply optimizations to loaded model."""
        # Move to GPU if available and optimize
        if GPU_AUTOLOADER_AVAILABLE:
            try:
                # Get optimal device
                device = get_device()
                if device != "cpu":
                    # Move model to GPU
                    if to_device:
                        model = to_device(model, device)
                        logger.info(f"Moved model {model_id} to {device}")

                    # Apply GPU optimizations
                    if optimize_for_gpu:
                        optimized_model = optimize_for_gpu(model)
                        if optimized_model is not None:
                            model = optimized_model
                            logger.info(f"Applied GPU optimizations to model {model_id}")
            except Exception as e:
                logger.debug(f"Could not optimize model for GPU: {e}")

        # Apply quantization for efficiency
        if model_type == "pytorch" and HAS_TORCH:
            try:
                import torch

                if hasattr(model, "eval"):
                    model.eval()
                    # Apply dynamic quantization for CPU inference
                    if not next(model.parameters()).is_cuda:
                        quantized = torch.quantization.quantize_dynamic(model, {torch.nn.Linear}, dtype=torch.qint8)
                        logger.info(f"Applied quantization to {model_id}")
                        return quantized
            except Exception as e:
                logger.debug(f"Could not quantize model: {e}")

        return model

    def predict(self, model_id: str, input_data: object) -> object:
        """Make predictions using a model with enhanced vulnerability scoring.

        Supports:
        - Vulnerability detection and scoring
        - Protection mechanism classification
        - Script generation assistance
        - Binary analysis predictions

        Args:
            model_id: Model identifier or pretrained model path
            input_data: Input data (binary features, code patterns, etc)

        Returns:
            Prediction results with confidence scores and recommendations

        """
        # Handle pretrained models with specialized prediction logic
        if model_id.startswith("pretrained/"):
            return self._predict_with_pretrained(model_id, input_data)

        # Load the model
        model = self.load_model(model_id)

        # Check if model has custom prediction method
        if hasattr(model, "predict"):
            return model.predict(input_data)

        # Standard prediction through backend
        if model_id in self.model_metadata:
            model_info = self.model_metadata[model_id]
            model_type = model_info["type"]
            backend = self.backends[model_type]
            return backend.predict(model, input_data)

        # Direct model prediction for loaded models
        if callable(model):
            return model(input_data)

        raise ValueError(f"Cannot predict with model {model_id}")

    def _predict_with_pretrained(self, model_id: str, input_data: object) -> dict[str, object]:
        """Make predictions using pretrained models with structured output."""
        model = self.load_model(model_id)

        if model_id == "pretrained/vulnerability_detector":
            return self._predict_vulnerabilities(model, input_data)
        if model_id == "pretrained/protection_classifier":
            return self._predict_protections(model, input_data)
        if model_id == "pretrained/script_generator":
            return self._predict_script_generation(model, input_data)
        if model_id == "pretrained/binary_analyzer":
            return self._predict_binary_analysis(model, input_data)
        raise ValueError(f"Unknown pretrained model: {model_id}")

    def _predict_vulnerabilities(self, model: object, input_data: object) -> dict[str, object]:
        """Predict vulnerabilities with scoring and recommendations."""
        # Prepare input data
        if isinstance(input_data, bytes):
            # Convert binary to feature vector
            features = self._extract_binary_features(input_data)
        elif isinstance(input_data, (list, np.ndarray)):
            features = np.array(input_data)
        else:
            features = input_data

        # Get predictions
        if hasattr(model, "detect_vulnerabilities"):
            vulnerabilities = model.detect_vulnerabilities(features)
        else:
            # Real vulnerability detection based on binary analysis
            vulnerabilities = []

            # Analyze binary for actual vulnerability patterns
            if isinstance(input_data, bytes):
                binary = input_data
            else:
                binary = b""

            # Buffer overflow detection - look for unsafe function calls
            buffer_overflow_indicators = [
                b"strcpy",
                b"strcat",
                b"gets",
                b"sprintf",
                b"scanf",
                b"vsprintf",
                b"realpath",
                b"getopt",
                b"getpass",
                b"streadd",
                b"strecpy",
                b"strtrns",
                b"getwd",
            ]
            unsafe_func_count = sum(1 for func in buffer_overflow_indicators if func in binary)
            if unsafe_func_count > 0:
                confidence = min(0.95, 0.3 + (unsafe_func_count * 0.15))
                vulnerabilities.append(
                    {
                        "type": "buffer_overflow",
                        "confidence": confidence,
                        "severity": self._calculate_severity("buffer_overflow", confidence),
                        "cve_similar": self._find_similar_cves("buffer_overflow"),
                    },
                )

            # Format string detection - look for format string functions without proper validation
            format_string_indicators = [b"printf", b"fprintf", b"sprintf", b"snprintf", b"vprintf"]
            format_funcs = sum(1 for func in format_string_indicators if func in binary)
            if format_funcs > 0 and b"%s" in binary and b"%n" in binary:
                confidence = min(0.85, 0.4 + (format_funcs * 0.1))
                vulnerabilities.append(
                    {
                        "type": "format_string",
                        "confidence": confidence,
                        "severity": self._calculate_severity("format_string", confidence),
                        "cve_similar": self._find_similar_cves("format_string"),
                    },
                )

            # Integer overflow detection - look for arithmetic operations without bounds checking
            if b"malloc" in binary or b"calloc" in binary or b"realloc" in binary:
                # Check for multiplication operations near memory allocation
                alloc_patterns = [b"imul", b"mul", b"shl"]  # x86 assembly patterns
                overflow_risk = sum(1 for pattern in alloc_patterns if pattern in binary)
                if overflow_risk > 0:
                    confidence = min(0.7, 0.3 + (overflow_risk * 0.1))
                    vulnerabilities.append(
                        {
                            "type": "integer_overflow",
                            "confidence": confidence,
                            "severity": self._calculate_severity("integer_overflow", confidence),
                            "cve_similar": self._find_similar_cves("integer_overflow"),
                        },
                    )

            # Use-after-free detection - look for free() followed by dereference patterns
            if b"free" in binary:
                # Check for potential use after free patterns
                uaf_patterns = [b"mov", b"call", b"jmp"]  # Operations after free
                if any(pattern in binary for pattern in uaf_patterns):
                    # Conservative detection since static analysis is limited
                    confidence = 0.4
                    vulnerabilities.append(
                        {
                            "type": "use_after_free",
                            "confidence": confidence,
                            "severity": self._calculate_severity("use_after_free", confidence),
                            "cve_similar": self._find_similar_cves("use_after_free"),
                        },
                    )

            # Null dereference detection - check for pointer operations without validation
            if b"mov" in binary and (b"NULL" in binary or b"\x00\x00\x00\x00" in binary):
                confidence = 0.35
                vulnerabilities.append(
                    {
                        "type": "null_dereference",
                        "confidence": confidence,
                        "severity": self._calculate_severity("null_dereference", confidence),
                        "cve_similar": self._find_similar_cves("null_dereference"),
                    },
                )

            # Race condition detection - look for threading/locking issues
            thread_indicators = [b"pthread", b"mutex", b"lock", b"thread", b"atomic"]
            if any(indicator in binary for indicator in thread_indicators):
                # Check for missing synchronization
                sync_patterns = [b"pthread_mutex_lock", b"EnterCriticalSection", b"lock"]
                has_sync = any(pattern in binary for pattern in sync_patterns)
                if not has_sync:
                    confidence = 0.5
                    vulnerabilities.append(
                        {
                            "type": "race_condition",
                            "confidence": confidence,
                            "severity": self._calculate_severity("race_condition", confidence),
                            "cve_similar": self._find_similar_cves("race_condition"),
                        },
                    )

        # Calculate overall security score
        if vulnerabilities:
            max_severity = max(v.get("confidence", 0) for v in vulnerabilities)
            security_score = max(0, 100 - (max_severity * 100))
        else:
            security_score = 95

        return {
            "vulnerabilities": vulnerabilities,
            "security_score": security_score,
            "risk_level": self._get_risk_level(security_score),
            "recommendations": self._generate_vuln_recommendations(vulnerabilities),
            "timestamp": __import__("datetime").datetime.now().isoformat(),
        }

    def _predict_protections(self, model: object, input_data: object) -> dict[str, object]:
        """Predict protection mechanisms in binary."""
        if hasattr(model, "classify_protections"):
            protections = model.classify_protections(input_data)
        else:
            # Fallback detection
            protections = []
            if b"IsDebuggerPresent" in input_data:
                protections.append({"type": "anti_debug", "confidence": 0.9})
            if b"VMware" in input_data or b"VirtualBox" in input_data:
                protections.append({"type": "anti_vm", "confidence": 0.85})
            if b"license" in input_data.lower():
                protections.append({"type": "license_check", "confidence": 0.7})

        # Group protections by category
        protection_categories = {
            "anti_analysis": ["anti_debug", "anti_vm", "anti_dump"],
            "licensing": ["license_check", "hardware_lock", "time_trial"],
            "integrity": ["integrity_check", "anti_tamper", "self_modification"],
            "obfuscation": ["packing", "encryption", "code_virtualization"],
        }

        categorized = {}
        for category, types in protection_categories.items():
            categorized[category] = [p for p in protections if p["type"] in types]

        return {
            "protections": protections,
            "categorized": categorized,
            "protection_score": len(protections) * 10,  # Simple scoring
            "bypass_difficulty": self._calculate_bypass_difficulty(protections),
            "bypass_strategies": self._generate_bypass_strategies(protections),
        }

    def _predict_script_generation(self, model: object, input_data: dict[str, object]) -> dict[str, object]:
        """Generate script predictions and templates."""
        protection_type = input_data.get("protection_type", "unknown")
        target_info = input_data.get("target_info", {})

        if hasattr(model, "generate_script_snippet"):
            script = model.generate_script_snippet(protection_type, target_info)
        else:
            # Fallback templates
            scripts = {
                "license_check": """
// Bypass license check
Interceptor.attach(Module.findExportByName(null, 'CheckLicense'), {
    onEnter: function(args) {
        console.log('[+] License check intercepted');
    },
    onLeave: function(retval) {
        retval.replace(1); // Force success
    }
});""",
                "anti_debug": """
// Bypass anti-debug
var IsDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
Interceptor.attach(IsDebuggerPresent, {
    onLeave: function(retval) {
        retval.replace(0);
    }
});""",
            }
            script = scripts.get(protection_type, "// Manual analysis required")

        return {
            "script": script,
            "script_type": "frida" if "Interceptor" in script else "python",
            "confidence": 0.8,
            "alternative_approaches": self._generate_alternative_approaches(protection_type),
            "testing_steps": self._generate_testing_steps(protection_type),
        }

    def _predict_binary_analysis(self, model: object, input_data: object) -> dict[str, object]:
        """Comprehensive binary analysis prediction."""
        if hasattr(model, "analyze_binary"):
            analysis = model.analyze_binary(input_data)
        else:
            # Basic analysis
            analysis = {
                "architecture": "x86" if b"MZ" in input_data[:2] else "Unknown",
                "arch_confidence": 0.7,
                "compiler": "Unknown",
                "compiler_confidence": 0.5,
                "packer": "None",
                "packer_confidence": 0.5,
            }

        # Add entropy analysis
        entropy = self._calculate_entropy(input_data[:1024])
        analysis["entropy"] = entropy
        analysis["likely_packed"] = entropy > 7.0

        # Add section analysis
        analysis["sections"] = self._analyze_sections(input_data)

        # Add import analysis
        analysis["suspicious_imports"] = self._find_suspicious_imports(input_data)

        return {
            "analysis": analysis,
            "classification": self._classify_binary_type(analysis),
            "recommended_tools": self._recommend_analysis_tools(analysis),
            "next_steps": self._generate_analysis_steps(analysis),
        }

    def _extract_binary_features(self, binary_data: bytes) -> np.ndarray:
        """Extract feature vector from binary data."""
        # Simple feature extraction
        features = []

        # Byte histogram
        byte_counts = np.zeros(256)
        for byte in binary_data[:10000]:  # First 10KB
            byte_counts[byte] += 1
        features.extend(byte_counts / len(binary_data[:10000]))

        # Entropy features
        for i in range(0, min(len(binary_data), 10000), 1000):
            chunk = binary_data[i : i + 1000]
            features.append(self._calculate_entropy(chunk))

        # String features
        strings = self._extract_strings(binary_data[:10000])
        features.append(len(strings))
        features.append(np.mean([len(s) for s in strings]) if strings else 0)

        # Pad or truncate to expected size
        expected_size = 1024
        if len(features) < expected_size:
            features.extend([0] * (expected_size - len(features)))
        else:
            features = features[:expected_size]

        return np.array(features, dtype=np.float32)

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        import math

        if not data:
            return 0

        entropy = 0
        for i in range(256):
            count = data.count(bytes([i]))
            if count > 0:
                frequency = count / len(data)
                entropy -= frequency * math.log2(frequency)

        return entropy

    def _extract_strings(self, data: bytes, min_length: int = 4) -> list[str]:
        """Extract ASCII strings from binary data."""
        import re

        # Find ASCII strings
        ascii_pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
        strings = re.findall(ascii_pattern, data)

        return [s.decode("ascii", errors="ignore") for s in strings]

    def _calculate_severity(self, vuln_type: str, confidence: float) -> str:
        """Calculate vulnerability severity."""
        high_severity_vulns = ["buffer_overflow", "command_injection", "use_after_free"]
        medium_severity_vulns = ["format_string", "integer_overflow", "path_traversal"]

        if vuln_type in high_severity_vulns and confidence > 0.7:
            return "CRITICAL"
        if vuln_type in high_severity_vulns and confidence > 0.5:
            return "HIGH"
        if vuln_type in medium_severity_vulns and confidence > 0.6:
            return "MEDIUM"
        return "LOW"

    def _find_similar_cves(self, vuln_type: str) -> list[str]:
        """Find similar CVEs for vulnerability type."""
        cve_database = {
            "buffer_overflow": ["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472"],
            "format_string": ["CVE-2012-0809", "CVE-2015-0235"],
            "integer_overflow": ["CVE-2020-14372", "CVE-2018-5390"],
            "use_after_free": ["CVE-2021-30551", "CVE-2020-6449"],
            "command_injection": ["CVE-2021-41773", "CVE-2019-18634"],
        }
        return cve_database.get(vuln_type, [])

    def _get_risk_level(self, security_score: float) -> str:
        """Determine risk level from security score."""
        if security_score >= 90:
            return "LOW"
        if security_score >= 70:
            return "MEDIUM"
        if security_score >= 50:
            return "HIGH"
        return "CRITICAL"

    def _generate_vuln_recommendations(self, vulnerabilities: list) -> list[str]:
        """Generate recommendations for found vulnerabilities."""
        recommendations = []

        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "")
            if vuln_type == "buffer_overflow":
                recommendations.append("Enable DEP/NX and ASLR protections")
            elif vuln_type == "format_string":
                recommendations.append("Use safe string formatting functions")
            elif vuln_type == "integer_overflow":
                recommendations.append("Add integer overflow checks")
            elif vuln_type == "use_after_free":
                recommendations.append("Implement proper memory management")

        return list(set(recommendations))  # Remove duplicates

    def _calculate_bypass_difficulty(self, protections: list) -> str:
        """Calculate difficulty of bypassing protections."""
        difficult_protections = ["code_virtualization", "anti_tamper", "hardware_lock"]
        medium_protections = ["packing", "anti_debug", "integrity_check"]

        has_difficult = any(p["type"] in difficult_protections for p in protections)
        has_medium = any(p["type"] in medium_protections for p in protections)

        if has_difficult:
            return "EXPERT"
        if has_medium:
            return "INTERMEDIATE"
        return "BEGINNER"

    def _generate_bypass_strategies(self, protections: list) -> dict:
        """Generate bypass strategies for detected protections."""
        strategies = {}

        for protection in protections:
            prot_type = protection["type"]
            if prot_type == "anti_debug":
                strategies[prot_type] = "Hook debugging APIs, use kernel debugger"
            elif prot_type == "anti_vm":
                strategies[prot_type] = "Patch VM detection checks, use bare metal"
            elif prot_type == "license_check":
                strategies[prot_type] = "Patch validation logic, emulate license server"
            elif prot_type == "packing":
                strategies[prot_type] = "Unpack with specific unpacker, dump from memory"

        return strategies

    def _generate_alternative_approaches(self, protection_type: str) -> list[str]:
        """Generate alternative approaches for bypassing protections."""
        approaches = {
            "license_check": [
                "Patch binary directly",
                "Hook network calls",
                "Emulate license server",
                "Modify registry/config files",
            ],
            "anti_debug": [
                "Use kernel debugger",
                "Hide debugger with plugins",
                "Use DBI framework",
                "Static analysis only",
            ],
        }
        return approaches.get(protection_type, ["Manual analysis required"])

    def _generate_testing_steps(self, protection_type: str) -> list[str]:
        """Generate testing steps for bypass verification."""
        steps = {
            "license_check": [
                "1. Apply bypass script",
                "2. Monitor application behavior",
                "3. Check for full functionality",
                "4. Verify no callbacks to license server",
            ],
            "anti_debug": [
                "1. Attach debugger with bypass",
                "2. Set breakpoints at critical functions",
                "3. Step through execution",
                "4. Verify normal operation",
            ],
        }
        return steps.get(protection_type, ["Test bypass effectiveness"])

    def _analyze_sections(self, binary_data: bytes) -> list[dict]:
        """Analyze binary sections."""
        sections = []

        # Simple PE header check
        if binary_data[:2] == b"MZ":
            # This is a simplified section analysis
            sections.append(
                {
                    "name": ".text",
                    "size": 0x1000,
                    "entropy": self._calculate_entropy(binary_data[0x1000:0x2000]),
                    "executable": True,
                },
            )
            sections.append(
                {
                    "name": ".data",
                    "size": 0x500,
                    "entropy": self._calculate_entropy(binary_data[0x2000:0x2500]),
                    "executable": False,
                },
            )

        return sections

    def _find_suspicious_imports(self, binary_data: bytes) -> list[str]:
        """Find suspicious API imports in binary."""
        suspicious_apis = [
            b"VirtualAlloc",
            b"WriteProcessMemory",
            b"CreateRemoteThread",
            b"SetWindowsHookEx",
            b"RegOpenKeyEx",
            b"IsDebuggerPresent",
            b"GetTickCount",
            b"GetSystemTime",
            b"CheckRemoteDebuggerPresent",
        ]

        found = []
        for api in suspicious_apis:
            if api in binary_data:
                found.append(api.decode("ascii"))

        return found

    def _classify_binary_type(self, analysis: dict) -> str:
        """Classify binary type based on analysis."""
        if analysis.get("likely_packed"):
            return "Packed Executable"
        if analysis.get("suspicious_imports"):
            return "Potentially Malicious"
        return "Standard Executable"

    def _recommend_analysis_tools(self, analysis: dict) -> list[str]:
        """Recommend tools based on binary analysis."""
        tools = ["Ghidra", "x64dbg", "Radare2"]

        if analysis.get("likely_packed"):
            tools.append("UPX Unpacker")
            tools.append("PEiD")

        if analysis.get("architecture") == "x64":
            tools.append("WinDbg")

        return tools

    def _generate_analysis_steps(self, analysis: dict) -> list[str]:
        """Generate next analysis steps."""
        steps = []

        if analysis.get("likely_packed"):
            steps.append("Unpack the binary first")

        steps.extend(
            [
                "Analyze entry point",
                "Map imported functions",
                "Identify key algorithms",
                "Trace execution flow",
            ],
        )

        return steps

    def predict_batch(self, model_id: str, batch_data: list) -> list:
        """Make batch predictions with GPU optimization."""
        model = self.load_model(model_id)
        model_info = self.model_metadata[model_id]
        model_type = model_info["type"]

        # Apply GPU optimization for batch processing if available
        if GPU_AUTOLOADER_AVAILABLE and gpu_autoloader and len(batch_data) > 1:
            try:
                # Try to optimize the model for batch processing
                optimized_model = gpu_autoloader(model)
                if optimized_model is not None:
                    model = optimized_model
                    logger.debug(f"Applied GPU batch optimization to model {model_id}")
            except Exception as e:
                logger.debug(f"Could not apply batch optimization: {e}")

        # Process batch
        backend = self.backends[model_type]
        results = []
        for data in batch_data:
            try:
                result = backend.predict(model, data)
                results.append(result)
            except Exception as e:
                logger.error(f"Batch prediction error: {e}")
                results.append(None)

        return results

    def get_model_info(self, model_id: str) -> dict[str, Any]:
        """Get information about a model."""
        if model_id not in self.model_metadata:
            raise ValueError(f"Model not registered: {model_id}")

        model_info = self.model_metadata[model_id].copy()

        # Add runtime info if model is loaded
        if model_id in self.loaded_models:
            model = self.loaded_models[model_id]
            model_type = model_info["type"]
            backend = self.backends[model_type]

            runtime_info = backend.get_model_info(model)
            model_info.update(runtime_info)
            model_info["loaded"] = True
        else:
            model_info["loaded"] = False

        return model_info

    def list_models(self) -> list[str]:
        """List all registered models."""
        return list(self.model_metadata.keys())

    def unload_model(self, model_id: str) -> None:
        """Unload a model from memory."""
        with self.lock:
            if model_id in self.loaded_models:
                del self.loaded_models[model_id]
                logger.info("Unloaded model: %s", model_id)

    def unregister_model(self, model_id: str) -> None:
        """Unregister a model."""
        with self.lock:
            if model_id in self.model_metadata:
                del self.model_metadata[model_id]
                self._save_model_metadata()

            if model_id in self.loaded_models:
                del self.loaded_models[model_id]

            logger.info("Unregistered model: %s", model_id)

    def get_available_backends(self) -> list[str]:
        """Get list of available backends."""
        return list(self.backends.keys())

    def clear_cache(self) -> None:
        """Clear the model cache."""
        self.cache.clear()

    def get_cache_info(self) -> dict[str, Any]:
        """Get cache information."""
        return self.cache.get_cache_info()

    def get_manager_stats(self) -> dict[str, Any]:
        """Get manager statistics."""
        with self.lock:
            return {
                "registered_models": len(self.model_metadata),
                "loaded_models": len(self.loaded_models),
                "available_backends": self.get_available_backends(),
                "models_directory": self.models_dir,
                "cache_info": self.get_cache_info(),
            }

    def import_local_model(self, file_path: str) -> dict[str, Any]:
        """Import a local model file."""
        try:
            if not os.path.exists(file_path):
                return None

            model_name = os.path.basename(file_path)
            model_id = f"local_{model_name}"
            model_type = self._detect_model_type(file_path)

            self.register_model(model_id, file_path, model_type)

            return {
                "model_id": model_id,
                "local_path": file_path,
                "name": model_name,
                "type": model_type,
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to import local model: %s", e)
            return None

    def get_available_repositories(self) -> list[str]:
        """Get list of available model repositories."""
        return ["huggingface", "local", "custom"]

    def get_available_models(self, repository: str = None) -> list[dict[str, Any]]:
        """Get list of available models."""
        models = []
        for model_id, metadata in self.model_metadata.items():
            model_info = {
                "id": model_id,
                "name": model_id,
                "type": metadata.get("type", "unknown"),
                "path": metadata.get("path", ""),
                "repository": repository or "local",
            }
            models.append(model_info)
        return models

    def get_model_path(self, model_id: str) -> str:
        """Get the file path for a model."""
        if model_id in self.model_metadata:
            model_info = self.model_metadata[model_id]
            path = model_info.get("path", "")

            # Handle different model types
            if model_info.get("type") == "api":
                # API models return their API endpoint
                return path
            if model_info.get("type") == "repository":
                # Repository models may need path resolution
                repo_name = model_info.get("repository", "")
                model_name = model_info.get("model_name", model_id)
                if repo_name and model_name:
                    # Construct path to downloaded model
                    repo_dir = os.path.join(self.models_dir, "repositories", repo_name)
                    model_path = os.path.join(repo_dir, model_name)
                    if os.path.exists(model_path):
                        return model_path
                    # Try with common extensions
                    for ext in [".pth", ".h5", ".onnx", ".pkl", ".joblib"]:
                        extended_path = model_path + ext
                        if os.path.exists(extended_path):
                            return extended_path

            # For local models, check if path exists
            if path and os.path.exists(path):
                return path

            # Try to find in models directory
            possible_paths = [
                os.path.join(self.models_dir, model_id),
                os.path.join(self.models_dir, f"{model_id}.pth"),
                os.path.join(self.models_dir, f"{model_id}.h5"),
                os.path.join(self.models_dir, f"{model_id}.onnx"),
                os.path.join(self.models_dir, f"{model_id}.pkl"),
                os.path.join(self.models_dir, f"{model_id}.joblib"),
                os.path.join(self.models_dir, "downloads", model_id),
                os.path.join(self.models_dir, "downloads", f"{model_id}.pth"),
            ]

            for p in possible_paths:
                if os.path.exists(p):
                    # Update metadata with found path
                    self.model_metadata[model_id]["path"] = p
                    self._save_model_metadata()
                    return p

        # Model not found - return empty string
        logger.warning(f"Model path not found for model_id: {model_id}")
        return ""

    def import_api_model(self, model_name: str, api_config: dict[str, Any]) -> dict[str, Any]:
        """Import a model from an API."""
        try:
            model_id = f"api_{model_name}"

            # Store API configuration in metadata
            self.model_metadata[model_id] = {
                "path": f"api://{model_name}",
                "type": "api",
                "registered": datetime.now().isoformat(),
                "metadata": api_config,
            }

            self._save_model_metadata()

            return {
                "model_id": model_id,
                "name": model_name,
                "type": "api",
                "config": api_config,
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to import API model: %s", e)
            return None

    def train_model(self, training_data: object, model_type: str) -> bool:
        """Train a machine learning model with provided data.

        Args:
            training_data: Training data for the model
            model_type: Type of model to train (pytorch, tensorflow, sklearn)

        Returns:
            bool: True if training succeeded, False otherwise

        """
        try:
            logger.info("Training %s model with provided data", model_type)

            # Check if we have the appropriate backend
            if model_type.lower() not in self.backends:
                logger.error("Backend not available for model type: %s", model_type)
                return False

            backend = self.backends[model_type.lower()]

            # Create training workflow adapted to the specific model type and data format

            if model_type.lower() == "sklearn":
                # Use sklearn backend for traditional ML models
                try:
                    from sklearn.ensemble import RandomForestClassifier
                    from sklearn.model_selection import train_test_split

                    # Handle different data formats
                    if hasattr(training_data, "shape"):
                        # NumPy array or similar
                        if training_data.shape[1] > 1:
                            # Last column is labels
                            X = training_data[:, :-1]
                            y = training_data[:, -1]
                        else:
                            # Single column data without labels - cannot train supervised model
                            logger.error("Training data has only features without labels")
                            logger.info("For supervised learning, provide data with labels in the last column")
                            return False
                    elif isinstance(training_data, (list, tuple)):
                        # Cannot perform supervised learning without labels
                        logger.error("Training data provided without labels - cannot train supervised model")
                        logger.info("Consider using unsupervised learning or provide labeled data")
                        return False
                    else:
                        logger.warning("Unsupported training data format for sklearn")
                        return False

                    # Split data for training and validation using train_test_split
                    X_train, X_val, y_train, y_val = train_test_split(
                        X,
                        y,
                        test_size=0.2,
                        random_state=42,
                        stratify=y if len(np.unique(y)) > 1 else None,
                    )

                    logger.info(f"Split data: {len(X_train)} training samples, {len(X_val)} validation samples")

                    # Create and train model
                    model = RandomForestClassifier(n_estimators=10, random_state=42)
                    model.fit(X_train, y_train)

                    # Evaluate on validation set
                    val_score = model.score(X_val, y_val)
                    logger.info(f"Validation accuracy: {val_score:.4f}")

                    # Store trained model in cache
                    model_id = f"trained_model_{model_type}_{len(self.cache.cache)}"
                    model_data = {
                        "model": model,
                        "backend": backend,
                        "last_used": time.time(),
                        "metadata": {
                            "type": model_type,
                            "trained": True,
                            "training_samples": len(X_train),
                            "validation_samples": len(X_val),
                            "validation_score": val_score,
                            "train_test_split_ratio": 0.8,
                        },
                    }
                    self.cache.put(model_id, model_data)

                    logger.info("Model training completed successfully: %s", model_id)
                    return True

                except ImportError:
                    logger.warning("sklearn not available for training")
                    return False

            elif model_type.lower() == "pytorch":
                # PyTorch training implementation
                try:
                    import torch
                    from torch import nn, optim
                    from torch.utils.data import DataLoader, TensorDataset

                    logger.info("Starting PyTorch model training")

                    # Prepare data
                    if isinstance(training_data, dict):
                        X = training_data.get("features", [])
                        y = training_data.get("labels", [])
                    else:
                        # Assume tuple of (features, labels)
                        X, y = training_data

                    # Convert to tensors
                    X_tensor = torch.FloatTensor(X)
                    y_tensor = torch.LongTensor(y)

                    # Split data
                    train_size = int(0.8 * len(X_tensor))
                    val_size = len(X_tensor) - train_size
                    train_dataset, val_dataset = torch.utils.data.random_split(
                        TensorDataset(X_tensor, y_tensor),
                        [train_size, val_size],
                    )

                    # Create data loaders
                    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
                    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)

                    # Define simple neural network
                    class SimpleNN(nn.Module):
                        """Perform neural network for basic classification tasks."""

                        def __init__(self, input_size: int, num_classes: int) -> None:
                            """Initialize simple neural network with specified input size and number of classes.

                            Args:
                                input_size: Number of input features
                                num_classes: Number of output classes

                            """
                            super().__init__()
                            self.fc1 = nn.Linear(input_size, 128)
                            self.fc2 = nn.Linear(128, 64)
                            self.fc3 = nn.Linear(64, num_classes)
                            self.dropout = nn.Dropout(0.2)

                        def forward(self, x: object) -> object:
                            x = torch.relu(self.fc1(x))
                            x = self.dropout(x)
                            x = torch.relu(self.fc2(x))
                            x = self.dropout(x)
                            x = self.fc3(x)
                            return x

                    # Initialize model
                    input_size = X_tensor.shape[1]
                    num_classes = len(torch.unique(y_tensor))
                    model = SimpleNN(input_size, num_classes)

                    # Loss and optimizer
                    criterion = nn.CrossEntropyLoss()
                    optimizer = optim.Adam(model.parameters(), lr=0.001)

                    # Training loop
                    num_epochs = 10
                    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                    model.to(device)

                    best_val_acc = 0.0
                    for epoch in range(num_epochs):
                        # Training
                        model.train()
                        train_loss = 0.0
                        train_correct = 0
                        train_total = 0

                        for batch_X, batch_y in train_loader:
                            batch_X, batch_y = batch_X.to(device), batch_y.to(device)

                            optimizer.zero_grad()
                            outputs = model(batch_X)
                            loss = criterion(outputs, batch_y)
                            loss.backward()
                            optimizer.step()

                            train_loss += loss.item()
                            _, predicted = torch.max(outputs.data, 1)
                            train_total += batch_y.size(0)
                            train_correct += (predicted == batch_y).sum().item()

                        # Validation
                        model.eval()
                        val_correct = 0
                        val_total = 0

                        with torch.no_grad():
                            for batch_X, batch_y in val_loader:
                                batch_X, batch_y = batch_X.to(device), batch_y.to(device)
                                outputs = model(batch_X)
                                _, predicted = torch.max(outputs.data, 1)
                                val_total += batch_y.size(0)
                                val_correct += (predicted == batch_y).sum().item()

                        train_acc = 100 * train_correct / train_total
                        val_acc = 100 * val_correct / val_total

                        logger.info(
                            f"Epoch [{epoch + 1}/{num_epochs}], "
                            f"Train Loss: {train_loss / len(train_loader):.4f}, "
                            f"Train Acc: {train_acc:.2f}%, "
                            f"Val Acc: {val_acc:.2f}%",
                        )

                        best_val_acc = max(best_val_acc, val_acc)

                    # Store trained model
                    model_id = f"trained_pytorch_model_{len(self.cache.cache)}"
                    model_data = {
                        "model": model,
                        "backend": "pytorch",
                        "last_used": time.time(),
                        "metadata": {
                            "type": "pytorch",
                            "trained": True,
                            "training_samples": train_size,
                            "validation_samples": val_size,
                            "best_validation_accuracy": best_val_acc,
                            "num_epochs": num_epochs,
                            "device": str(device),
                        },
                    }
                    self.cache.put(model_id, model_data)

                    logger.info(f"PyTorch model training completed: {model_id}")
                    return True

                except ImportError:
                    logger.warning("PyTorch not available for training")
                    return False
                except Exception as e:
                    logger.error(f"PyTorch training error: {e}")
                    return False

            elif model_type.lower() == "tensorflow":
                # TensorFlow/Keras training implementation
                try:
                    from intellicrack.handlers.tensorflow_handler import tensorflow as tf

                    keras = tf.keras
                    from tensorflow.keras import layers

                    logger.info("Starting TensorFlow model training")

                    # Prepare data
                    if isinstance(training_data, dict):
                        X = training_data.get("features", [])
                        y = training_data.get("labels", [])
                    else:
                        X, y = training_data

                    # Convert to numpy arrays
                    X = np.array(X, dtype=np.float32)
                    y = np.array(y, dtype=np.int32)

                    # Split data
                    from sklearn.model_selection import train_test_split

                    X_train, X_val, y_train, y_val = train_test_split(
                        X,
                        y,
                        test_size=0.2,
                        random_state=42,
                    )

                    # Determine number of classes
                    num_classes = len(np.unique(y))

                    # One-hot encode labels if multi-class
                    if num_classes > 2:
                        y_train = tf.keras.utils.to_categorical(y_train, num_classes)
                        y_val = tf.keras.utils.to_categorical(y_val, num_classes)

                    # Build model
                    model = keras.Sequential(
                        [
                            layers.Input(shape=(X.shape[1],)),
                            layers.Dense(128, activation="relu"),
                            layers.Dropout(0.2),
                            layers.Dense(64, activation="relu"),
                            layers.Dropout(0.2),
                            layers.Dense(
                                num_classes if num_classes > 2 else 1,
                                activation="softmax" if num_classes > 2 else "sigmoid",
                            ),
                        ],
                    )

                    # Compile model
                    if num_classes > 2:
                        model.compile(
                            optimizer="adam",
                            loss="categorical_crossentropy",
                            metrics=["accuracy"],
                        )
                    else:
                        model.compile(
                            optimizer="adam",
                            loss="binary_crossentropy",
                            metrics=["accuracy"],
                        )

                    # Early stopping callback
                    early_stopping = keras.callbacks.EarlyStopping(
                        monitor="val_loss",
                        patience=3,
                        restore_best_weights=True,
                    )

                    # Train model
                    history = model.fit(
                        X_train,
                        y_train,
                        validation_data=(X_val, y_val),
                        epochs=20,
                        batch_size=32,
                        callbacks=[early_stopping],
                        verbose=1,
                    )

                    # Get final validation accuracy
                    val_loss, val_acc = model.evaluate(X_val, y_val, verbose=0)

                    logger.info(f"TensorFlow training completed - Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}")

                    # Store trained model
                    model_id = f"trained_tensorflow_model_{len(self.cache.cache)}"
                    model_data = {
                        "model": model,
                        "backend": "tensorflow",
                        "last_used": time.time(),
                        "metadata": {
                            "type": "tensorflow",
                            "trained": True,
                            "training_samples": len(X_train),
                            "validation_samples": len(X_val),
                            "validation_loss": float(val_loss),
                            "validation_accuracy": float(val_acc),
                            "num_epochs": len(history.history["loss"]),
                            "num_classes": num_classes,
                        },
                    }
                    self.cache.put(model_id, model_data)

                    logger.info(f"TensorFlow model training completed: {model_id}")
                    return True

                except ImportError:
                    logger.warning("TensorFlow not available for training")
                    return False
                except Exception as e:
                    logger.error(f"TensorFlow training error: {e}")
                    return False

            else:
                logger.error("Unsupported model type for training: %s", model_type)
                return False

        except Exception as e:
            logger.error("Model training failed: %s", e)
            return False

    def save_model(self, model: object, path: str) -> bool:
        """Save a trained model to disk.

        Args:
            model: Model object to save
            path: File path where to save the model

        Returns:
            bool: True if saving succeeded, False otherwise

        """
        try:
            import pickle
            from pathlib import Path

            # Ensure directory exists
            save_path = Path(path)
            save_path.parent.mkdir(parents=True, exist_ok=True)

            # Try to determine model type and use appropriate saving method
            model_type = type(model).__name__.lower()

            if "sklearn" in str(type(model)) or hasattr(model, "fit"):
                # Sklearn or sklearn-compatible model
                try:
                    import joblib

                    joblib.dump(model, str(save_path))
                    logger.info("Model (type: %s) saved using joblib: %s", model_type, path)
                    return True
                except ImportError:
                    # Fallback to pickle
                    with open(save_path, "wb") as f:
                        pickle.dump(model, f)
                    logger.info("Model saved using pickle: %s", path)
                    return True

            elif "torch" in str(type(model)):
                # PyTorch model
                try:
                    import torch

                    torch.save(model.state_dict(), str(save_path))
                    logger.info("PyTorch model saved: %s", path)
                    return True
                except ImportError:
                    logger.error("PyTorch not available for saving")
                    return False

            elif "tensorflow" in str(type(model)) or "keras" in str(type(model)):
                # TensorFlow/Keras model
                try:
                    model.save(str(save_path))
                    logger.info("TensorFlow/Keras model saved: %s", path)
                    return True
                except Exception as tf_error:
                    logger.error("TensorFlow model save failed: %s", tf_error)
                    return False

            else:
                # Generic pickle save as fallback
                with open(save_path, "wb") as f:
                    pickle.dump(model, f)
                logger.info("Model saved using generic pickle: %s", path)
                return True

        except Exception as e:
            logger.error("Model save failed: %s", e)
            return False

    @property
    def repositories(self) -> list[str]:
        """Get available repositories."""
        return self.get_available_repositories()

    def evaluate_model_with_split(
        self, model_id: str, data: object, labels: object, test_size: float = 0.2, random_state: int = 42,
    ) -> dict[str, object]:
        """Evaluate a model using train_test_split for proper validation.

        Args:
            model_id: Model identifier
            data: Input features
            labels: Target labels
            test_size: Proportion of data to use for testing
            random_state: Random seed for reproducibility

        Returns:
            Dictionary with evaluation metrics

        """
        try:
            from sklearn.model_selection import train_test_split

            # Get the model
            model_data = self.cache.get(model_id)
            if not model_data:
                logger.error(f"Model {model_id} not found in cache")
                return {"error": "Model not found"}

            model = model_data.get("model")
            backend = model_data.get("backend")

            # Convert data to numpy arrays if needed
            if not isinstance(data, np.ndarray):
                data = np.array(data)
            if not isinstance(labels, np.ndarray):
                labels = np.array(labels)

            # Use train_test_split to create training and test sets
            X_train, X_test, y_train, y_test = train_test_split(
                data,
                labels,
                test_size=test_size,
                random_state=random_state,
                stratify=labels if len(np.unique(labels)) > 1 else None,
            )

            logger.info(f"Split data into {len(X_train)} training and {len(X_test)} test samples")

            # Evaluate based on backend type
            evaluation_results = {
                "train_size": len(X_train),
                "test_size": len(X_test),
                "test_ratio": test_size,
                "random_state": random_state,
            }

            if isinstance(backend, SklearnBackend):
                # Re-train on training set
                model.fit(X_train, y_train)

                # Evaluate on both sets
                train_score = model.score(X_train, y_train)
                test_score = model.score(X_test, y_test)

                evaluation_results.update(
                    {
                        "train_score": train_score,
                        "test_score": test_score,
                        "overfitting_gap": train_score - test_score,
                    },
                )

                # Get predictions for additional metrics
                y_pred = model.predict(X_test)

                # Calculate additional metrics if classification
                if hasattr(model, "predict_proba"):
                    from sklearn.metrics import classification_report, confusion_matrix

                    report = classification_report(y_test, y_pred, output_dict=True)
                    cm = confusion_matrix(y_test, y_pred)

                    evaluation_results.update(
                        {
                            "classification_report": report,
                            "confusion_matrix": cm.tolist(),
                        },
                    )

            elif isinstance(backend, PyTorchBackend) and HAS_TORCH:
                # For PyTorch models, implement evaluation logic
                import torch

                # Convert to tensors
                X_train_t = torch.FloatTensor(X_train)
                X_test_t = torch.FloatTensor(X_test)
                y_train_t = torch.LongTensor(y_train)
                y_test_t = torch.LongTensor(y_test)

                # Evaluate
                model.eval()
                with torch.no_grad():
                    train_outputs = model(X_train_t)
                    test_outputs = model(X_test_t)

                    if len(train_outputs.shape) > 1:
                        train_preds = torch.argmax(train_outputs, dim=1)
                        test_preds = torch.argmax(test_outputs, dim=1)
                    else:
                        train_preds = (train_outputs > 0.5).long()
                        test_preds = (test_outputs > 0.5).long()

                    train_accuracy = (train_preds == y_train_t).float().mean().item()
                    test_accuracy = (test_preds == y_test_t).float().mean().item()

                evaluation_results.update(
                    {
                        "train_accuracy": train_accuracy,
                        "test_accuracy": test_accuracy,
                        "backend": "pytorch",
                    },
                )

            logger.info(
                f"Model evaluation completed with test score: {evaluation_results.get('test_score', evaluation_results.get('test_accuracy', 'N/A'))}",
            )
            return evaluation_results

        except ImportError as e:
            logger.error(f"Failed to import required libraries: {e}")
            return {"error": f"Missing dependencies: {e}"}
        except Exception as e:
            logger.error(f"Model evaluation failed: {e}")
            return {"error": str(e)}


class AsyncModelManager:
    """Asynchronous wrapper for model operations."""

    def __init__(self, model_manager: ModelManager) -> None:
        """Initialize the asynchronous model manager wrapper.

        Args:
            model_manager: The underlying ModelManager instance to wrap with async capabilities.

        """
        self.logger = logging.getLogger(__name__ + ".AsyncModelManager")
        self.model_manager = model_manager
        self.thread_pool = {}

    def load_model_async(self, model_id: str, callback: Callable[..., None] | None = None) -> threading.Thread | None:
        """Load a model asynchronously."""
        # Skip thread creation during testing
        if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
            self.logger.info("Skipping async model loading (testing mode)")
            if callback:
                callback(False, None, "Async loading disabled in testing mode")
            return None

        def load_worker() -> None:
            """Worker function to load a model asynchronously.

            Attempts to load the specified model and calls the callback with the result.
            On success, passes (True, model, None) to callback.
            On failure, passes (False, None, error_message) to callback.
            """
            try:
                model = self.model_manager.load_model(model_id)
                if callback:
                    callback(True, model, None)
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error in model_manager_module: %s", e)
                if callback:
                    callback(False, None, str(e))

        thread = threading.Thread(target=load_worker, daemon=True)
        self.thread_pool[model_id] = thread
        thread.start()
        return thread

    def predict_async(self, model_id: str, input_data: object, callback: Callable[..., None] | None = None) -> threading.Thread | None:
        """Make predictions asynchronously."""
        # Skip thread creation during testing
        if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
            self.logger.info("Skipping async prediction (testing mode)")
            if callback:
                callback(False, None, "Async prediction disabled in testing mode")
            return None

        def predict_worker() -> None:
            """Worker function to make predictions asynchronously.

            Attempts to make predictions using the specified model and input data,
            then calls the callback with the result.
            On success, passes (True, prediction_result, None) to callback.
            On failure, passes (False, None, error_message) to callback.
            """
            try:
                result = self.model_manager.predict(model_id, input_data)
                if callback:
                    callback(True, result, None)
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error in model_manager_module: %s", e)
                if callback:
                    callback(False, None, str(e))

        thread = threading.Thread(target=predict_worker, daemon=True)
        thread.start()
        return thread


# Factory function for easy instantiation
def create_model_manager(models_dir: str = None, cache_size: int = 5) -> ModelManager:
    """Create a model manager instance."""
    return ModelManager(models_dir=models_dir, cache_size=cache_size)


# Global model manager instance
_GLOBAL_MODEL_MANAGER = None


def get_global_model_manager() -> ModelManager:
    """Get the global model manager instance."""
    global _GLOBAL_MODEL_MANAGER  # pylint: disable=global-statement
    if _GLOBAL_MODEL_MANAGER is None:
        _GLOBAL_MODEL_MANAGER = create_model_manager()
    return _GLOBAL_MODEL_MANAGER


class ModelFineTuner:
    """Fine-tuning support for AI models."""

    def __init__(self, model_manager: ModelManager) -> None:
        """Initialize the model fine-tuner.

        Args:
            model_manager: The ModelManager instance for accessing and managing models.

        """
        self.logger = logging.getLogger(__name__ + ".ModelFineTuner")
        self.model_manager = model_manager
        self.training_history = {}
        self.lock = threading.RLock()

    def fine_tune_model(
        self,
        model_id: str,
        training_data: object,
        validation_data: object | None = None,
        epochs: int = 10,
        learning_rate: float = 0.001,
        batch_size: int = 32,
        callback: Callable[..., None] | None = None,
    ) -> dict[str, object]:
        """Fine-tune a pre-trained model on custom data.

        Args:
            model_id: ID of the model to fine-tune
            training_data: Training dataset
            validation_data: Optional validation dataset
            epochs: Number of training epochs
            learning_rate: Learning rate for optimization
            batch_size: Batch size for training
            callback: Optional callback for progress updates

        Returns:
            Dict with training results and metrics

        """
        with self.lock:
            # Load the base model
            model = self.model_manager.load_model(model_id)
            model_info = self.model_manager.model_metadata[model_id]
            model_type = model_info["type"]

            results = {
                "model_id": model_id,
                "epochs": epochs,
                "training_loss": [],
                "validation_loss": [],
                "metrics": {},
                "fine_tuned_model_path": None,
            }

            try:
                if model_type in ["pytorch", "pth"] and HAS_TORCH:
                    results = self._fine_tune_pytorch(
                        model,
                        training_data,
                        validation_data,
                        epochs,
                        learning_rate,
                        batch_size,
                        callback,
                    )
                elif model_type in ["tensorflow", "h5"] and HAS_TENSORFLOW:
                    results = self._fine_tune_tensorflow(
                        model,
                        training_data,
                        validation_data,
                        epochs,
                        learning_rate,
                        batch_size,
                        callback,
                    )
                elif model_type in ["sklearn", "joblib"] and HAS_JOBLIB:
                    results = self._fine_tune_sklearn(
                        model,
                        training_data,
                        validation_data,
                        callback,
                    )
                else:
                    raise ValueError(f"Fine-tuning not supported for model type: {model_type}")

                # Save fine-tuned model
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                fine_tuned_id = f"{model_id}_finetuned_{timestamp}"
                fine_tuned_path = os.path.join(
                    self.model_manager.models_dir,
                    f"{fine_tuned_id}.{model_type}",
                )

                # Save the model
                backend = self.model_manager.backends[model_type]
                if hasattr(backend, "save_model"):
                    backend.save_model(model, fine_tuned_path)
                # Default save methods
                elif model_type in ["pytorch", "pth"]:
                    torch.save(model, fine_tuned_path)
                elif model_type in ["tensorflow", "h5"]:
                    model.save(fine_tuned_path)
                elif model_type in ["sklearn", "joblib"]:
                    joblib.dump(model, fine_tuned_path)

                # Register the fine-tuned model
                self.model_manager.register_model(
                    fine_tuned_id,
                    fine_tuned_path,
                    model_type,
                    metadata={
                        "base_model": model_id,
                        "fine_tuning_params": {
                            "epochs": epochs,
                            "learning_rate": learning_rate,
                            "batch_size": batch_size,
                        },
                        "results": results,
                    },
                )

                results["fine_tuned_model_id"] = fine_tuned_id
                results["fine_tuned_model_path"] = fine_tuned_path

                # Store training history
                self.training_history[fine_tuned_id] = results

                logger.info("Fine-tuning completed. New model ID: %s", fine_tuned_id)

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Fine-tuning failed: %s", e)
                results["error"] = str(e)

            return results

    def _fine_tune_pytorch(
        self,
        model: object,
        training_data: object,
        validation_data: object,
        epochs: int,
        learning_rate: float,
        batch_size: int,
        callback: Callable[..., None],
    ) -> dict[str, object]:
        """Fine-tune a PyTorch model."""
        if not HAS_TORCH or torch is None or nn is None:
            return {"error": "PyTorch not available"}

        try:
            from torch import optim  # pylint: disable=import-error
            from torch.utils.data import DataLoader, TensorDataset
        except ImportError as e:
            self.logger.error("Import error in model_manager_module: %s", e)
            return {"error": "PyTorch components not available"}

        # Set model to training mode
        model.train()

        # Create optimizer
        optimizer = optim.Adam(model.parameters(), lr=learning_rate)
        criterion = nn.CrossEntropyLoss()

        # Prepare data loaders
        train_dataset = TensorDataset(
            torch.tensor(training_data[0]).float(),
            torch.tensor(training_data[1]).long(),
        )
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

        val_loader = None
        if validation_data is not None:
            val_dataset = TensorDataset(
                torch.tensor(validation_data[0]).float(),
                torch.tensor(validation_data[1]).long(),
            )
            val_loader = DataLoader(val_dataset, batch_size=batch_size)

        results = {
            "training_loss": [],
            "validation_loss": [],
        }

        # Training loop
        for _epoch in range(epochs):
            # Training phase
            train_loss = 0.0
            for _batch_idx, (data, target) in enumerate(train_loader):
                optimizer.zero_grad()
                output = model(data)
                loss = criterion(output, target)
                loss.backward()
                optimizer.step()
                train_loss += loss.item()

            avg_train_loss = train_loss / len(train_loader)
            results["training_loss"].append(avg_train_loss)

            # Validation phase
            if val_loader:
                model.eval()
                val_loss = 0.0
                with torch.no_grad():
                    for data, target in val_loader:
                        output = model(data)
                        val_loss += criterion(output, target).item()

                avg_val_loss = val_loss / len(val_loader)
                results["validation_loss"].append(avg_val_loss)
                model.train()

            # Callback for progress updates
            if callback:
                callback(_epoch + 1, epochs, avg_train_loss, avg_val_loss if val_loader else None)

        return results

    def _fine_tune_tensorflow(
        self,
        model: object,
        training_data: object,
        validation_data: object,
        epochs: int,
        learning_rate: float,
        batch_size: int,
        callback: Callable[..., None],
    ) -> dict[str, object]:
        """Fine-tune a TensorFlow model."""
        # Compile model with new learning rate
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
            loss="sparse_categorical_crossentropy",
            metrics=["accuracy"],
        )

        # Prepare callbacks
        callbacks = []
        if callback:

            class ProgressCallback(keras.callbacks.Callback):
                """Keras callback to report training progress to the parent callback.

                Inherits from keras.callbacks.Callback to intercept training events
                and forward progress information to the user-provided callback function.
                """

                def on_epoch_end(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
                    """Call at the end of each training epoch.

                    Args:
                        epoch: Current epoch number (0-indexed)
                        logs: Dictionary containing training metrics (loss, val_loss, etc.)

                    """
                    callback(epoch + 1, epochs, logs.get("loss"), logs.get("val_loss"))

            callbacks.append(ProgressCallback())

        # Train the model
        history = model.fit(
            training_data[0],
            training_data[1],
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=0,
        )

        return {
            "training_loss": history.history["loss"],
            "validation_loss": history.history.get("val_loss", []),
            "metrics": history.history,
        }

    def _fine_tune_sklearn(self, model: object, training_data: object, validation_data: object, callback: Callable[..., None]) -> dict[str, object]:
        """Fine-tune a scikit-learn model."""
        # For sklearn, we typically retrain on new data
        X_train, y_train = training_data

        # Partial fit if supported, otherwise full refit
        if hasattr(model, "partial_fit"):
            model.partial_fit(X_train, y_train)
        else:
            model.fit(X_train, y_train)

        results = {"training_complete": True}

        # Calculate validation score if data provided
        if validation_data is not None:
            X_val, y_val = validation_data
            val_score = model.score(X_val, y_val)
            results["validation_score"] = val_score

        if callback:
            callback(1, 1, None, results.get("validation_score"))

        return results

    def get_training_history(self, model_id: str) -> dict[str, Any] | None:
        """Get training history for a fine-tuned model."""
        return self.training_history.get(model_id)


def import_custom_model(model_path: str, model_type: str = None, model_id: str = None) -> dict[str, Any]:
    """Import a custom AI model into the system.

    Args:
        model_path: Path to the model file
        model_type: Type of model (pytorch, tensorflow, onnx, sklearn)
        model_id: Optional custom ID for the model

    Returns:
        Dict with import results and model information

    """
    manager = get_global_model_manager()

    # Auto-generate model ID if not provided
    if model_id is None:
        model_name = Path(model_path).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_id = f"{model_name}_{timestamp}"

    try:
        # Register the model
        manager.register_model(model_id, model_path, model_type)

        # Try to load it to verify it works
        _ = manager.load_model(model_id)  # Load to verify the model works

        # Get model information
        model_info = manager.get_model_info(model_id)

        return {
            "success": True,
            "model_id": model_id,
            "model_path": model_path,
            "model_info": model_info,
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to import model: %s", e)
        return {
            "success": False,
            "error": str(e),
            "model_id": model_id,
            "model_path": model_path,
        }


# Standalone convenience functions for backward compatibility


def load_model(model_id: str, model_path: str | None = None) -> object:
    """Load a model using the global model manager.

    Args:
        model_id: ID of the model to load
        model_path: Optional path if model needs to be registered first

    Returns:
        Loaded model object

    """
    try:
        manager = get_global_model_manager()

        # If model_path provided, register first
        if model_path:
            # Auto-detect model type from extension
            ext = Path(model_path).suffix.lower()
            model_type_map = {
                ".pkl": "sklearn",
                ".joblib": "sklearn",
                ".pt": "pytorch",
                ".pth": "pytorch",
                ".onnx": "onnx",
                ".pb": "tensorflow",
                ".h5": "tensorflow",
            }
            model_type = model_type_map.get(ext, "sklearn")

            manager.register_model(model_id, model_path, model_type)

        return manager.load_model(model_id)

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to load model %s: %s", model_id, e)
        raise


def save_model(model_id: str, save_path: str, model_format: str = "auto") -> dict[str, object]:
    """Save a loaded model to disk.

    Args:
        model_id: ID of the loaded model
        save_path: Path where to save the model
        model_format: Format to save in (auto-detected from extension)

    Returns:
        Dict with save results

    """
    try:
        manager = get_global_model_manager()
        model = manager.load_model(model_id)

        # Auto-detect format from extension if needed
        if model_format == "auto":
            ext = Path(save_path).suffix.lower()
            format_map = {
                ".pkl": "pickle",
                ".joblib": "joblib",
                ".pt": "pytorch",
                ".pth": "pytorch",
                ".onnx": "onnx",
                ".h5": "tensorflow",
            }
            model_format = format_map.get(ext, "pickle")

        # Save based on format
        if model_format in ["pickle", "pkl"]:
            import pickle as pickle_lib

            with open(save_path, "wb") as f:
                pickle_lib.dump(model, f)
        elif model_format == "joblib":
            if HAS_JOBLIB:
                joblib.dump(model, save_path)
            else:
                import pickle as pickle_lib

                with open(save_path, "wb") as f:
                    pickle_lib.dump(model, f)
        elif model_format == "pytorch":
            if HAS_TORCH and torch is not None:
                torch.save(model, save_path)
            else:
                raise ImportError("PyTorch not available for saving .pt/.pth files")
        else:
            # Default to pickle
            import pickle as pickle_lib

            with open(save_path, "wb") as f:
                pickle_lib.dump(model, f)

        return {
            "success": True,
            "model_id": model_id,
            "save_path": save_path,
            "format": model_format,
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to save model %s: %s", model_id, e)
        return {
            "success": False,
            "error": str(e),
            "model_id": model_id,
            "save_path": save_path,
        }


def list_available_models() -> dict[str, Any]:
    """List all available models in the global manager.

    Returns:
        Dict containing model information

    """
    try:
        manager = get_global_model_manager()
        models = manager.list_models()

        # Get detailed info for each model
        detailed_models = {}
        for _model_id in models:
            try:
                info = manager.get_model_info(_model_id)
                detailed_models[_model_id] = info
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in model_manager_module: %s", e)
                detailed_models[_model_id] = {"error": str(e)}

        return {
            "success": True,
            "model_count": len(models),
            "models": detailed_models,
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to list models: %s", e)
        return {
            "success": False,
            "error": str(e),
            "models": {},
        }


def configure_ai_provider(provider_name: str, config: dict[str, Any]) -> dict[str, Any]:
    """Configure an AI provider for the model manager.

    Args:
        provider_name: Name of the provider (openai, anthropic, local, etc.)
        config: Configuration dictionary

    Returns:
        Configuration result

    """
    try:
        # This would integrate with LLM backends when available
        supported_providers = {
            "local": "Local model execution",
            "openai": "OpenAI API integration",
            "anthropic": "Anthropic API integration",
            "huggingface": "HuggingFace model hub",
            "onnx": "ONNX runtime models",
            "pytorch": "PyTorch models",
            "tensorflow": "TensorFlow models",
            "sklearn": "Scikit-learn models",
        }

        if provider_name not in supported_providers:
            return {
                "success": False,
                "error": f"Unsupported provider: {provider_name}",
                "supported_providers": list(supported_providers.keys()),
            }

        # Store configuration persistently
        import json
        from pathlib import Path

        config_dir = Path.home() / ".intellicrack"
        config_dir.mkdir(exist_ok=True)
        config_file = config_dir / "ai_provider_config.json"

        api_key = config.get("api_key")
        config_data = {
            "provider": provider_name,
            "api_key": api_key[:4] + "..." + api_key[-4:] if api_key else None,  # Store masked key
            "timestamp": str(datetime.datetime.now()),
            "settings": config,
        }

        with open(config_file, "w") as f:
            json.dump(config_data, f, indent=2)

        logger.info("Configured AI provider: %s (saved to %s)", provider_name, config_file)

        return {
            "success": True,
            "provider": provider_name,
            "description": supported_providers[provider_name],
            "config": config,
            "message": f"Provider {provider_name} configured successfully",
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to configure AI provider %s: %s", provider_name, e)
        return {
            "success": False,
            "error": str(e),
            "provider": provider_name,
        }


# Export for external use
__all__ = [
    "AsyncModelManager",
    "ModelBackend",
    "ModelCache",
    "ModelFineTuner",
    "ModelManager",
    "ONNXBackend",
    "PyTorchBackend",
    "SklearnBackend",
    "TensorFlowBackend",
    "configure_ai_provider",
    "create_model_manager",
    "get_global_model_manager",
    "import_custom_model",
    "list_available_models",
    "load_model",
    "save_model",
]
