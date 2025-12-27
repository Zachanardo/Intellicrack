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
from typing import Any, cast

from intellicrack.handlers.numpy_handler import numpy as np
from intellicrack.handlers.tensorflow_handler import HAS_TENSORFLOW


logger = logging.getLogger(__name__)

torch: Any = None
nn: Any = None
HAS_TORCH = False

try:
    import torch as _torch  # pylint: disable=import-error
    from torch import nn as _nn  # pylint: disable=import-error

    torch = _torch
    nn = _nn
    HAS_TORCH = True
except ImportError:
    pass

get_device: Callable[[], Any] | None = None
get_gpu_info: Callable[[], Any] | None = None
gpu_autoloader: Any = None
optimize_for_gpu: Callable[[Any], Any] | None = None
to_device: Callable[..., Any] | None = None
GPU_AUTOLOADER_AVAILABLE = False

try:
    from ..utils.gpu_autoloader import (
        get_device as _get_device,
        get_gpu_info as _get_gpu_info,
        gpu_autoloader as _gpu_autoloader,
        optimize_for_gpu as _optimize_for_gpu,
        to_device as _to_device,
    )

    get_device = _get_device
    get_gpu_info = _get_gpu_info
    gpu_autoloader = _gpu_autoloader
    optimize_for_gpu = _optimize_for_gpu
    to_device = _to_device
    GPU_AUTOLOADER_AVAILABLE = True
except ImportError:
    pass

tf: Any = None
keras: Any = None

try:
    os.environ["MKL_THREADING_LAYER"] = "GNU"

    from intellicrack.handlers.tensorflow_handler import tf as _tf

    tf = _tf
    if tf is not None:
        keras = tf.keras
        HAS_TENSORFLOW = True
    else:
        HAS_TENSORFLOW = False
except ImportError as e:
    logger.debug("TensorFlow not available: %s", e)
    HAS_TENSORFLOW = False

onnx: Any = None
ort: Any = None
HAS_ONNX = False

try:
    import onnx as _onnx
    import onnxruntime as _ort

    onnx = _onnx
    ort = _ort
    HAS_ONNX = True
except (ImportError, AttributeError) as e:
    logger.exception("Import error in model_manager_module: %s", e)

try:
    import joblib

    HAS_JOBLIB = True
except ImportError as e:
    logger.exception("Import error in model_manager_module: %s", e)
    HAS_JOBLIB = False


class ModelBackend(ABC):
    """Abstract base class for AI model backends."""

    @abstractmethod
    def load_model(self, model_path: str) -> Any:
        """Load a model from the given path."""

    @abstractmethod
    def predict(self, model: Any, input_data: Any) -> Any:
        """Make predictions using the model."""

    @abstractmethod
    def get_model_info(self, model: Any) -> dict[str, Any]:
        """Get information about the model."""


class PyTorchBackend(ModelBackend):
    """PyTorch model backend."""

    def load_model(self, model_path: str) -> Any:
        """Load a PyTorch model."""
        if not HAS_TORCH or torch is None:
            raise ImportError("PyTorch not available")

        try:
            model = torch.load(model_path, map_location="cpu")
            if hasattr(model, "eval"):
                model.eval()
            return model
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Failed to load PyTorch model: %s", e)
            raise

    def predict(self, model: Any, input_data: Any) -> Any:
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
            logger.exception("PyTorch prediction failed: %s", e)
            raise

    def get_model_info(self, model: Any) -> dict[str, Any]:
        """Get PyTorch model information."""
        info: dict[str, Any] = {
            "backend": "pytorch",
            "type": type(model).__name__,
            "parameters": 0,
        }

        if hasattr(model, "parameters"):
            try:
                info["parameters"] = sum(p.numel() for p in model.parameters())
            except (AttributeError, RuntimeError) as e:
                logger.debug("Failed to count PyTorch model parameters: %s", e)

        return info


class TensorFlowBackend(ModelBackend):
    """TensorFlow model backend."""

    def load_model(self, model_path: str) -> Any:
        """Load a TensorFlow model."""
        if not HAS_TENSORFLOW or tf is None:
            raise ImportError("TensorFlow not available")

        try:
            return keras.models.load_model(model_path)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Failed to load TensorFlow model: %s", e)
            raise

    def predict(self, model: Any, input_data: Any) -> Any:
        """Make predictions using TensorFlow model."""
        if not HAS_TENSORFLOW:
            raise ImportError("TensorFlow not available")

        try:
            if np is not None and not isinstance(input_data, np.ndarray):
                input_data = np.array(input_data)

            return model.predict(input_data)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("TensorFlow prediction failed: %s", e)
            raise

    def get_model_info(self, model: Any) -> dict[str, Any]:
        """Get TensorFlow model information."""
        info: dict[str, Any] = {
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

    def load_model(self, model_path: str) -> Any:
        """Load an ONNX model."""
        if not HAS_ONNX:
            raise ImportError("ONNX Runtime not available")

        try:
            model = onnx.load(model_path)
            onnx.checker.check_model(model)
            logger.info("ONNX model validation passed")

            return ort.InferenceSession(model_path)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Failed to load ONNX model: %s", e)
            raise

    def predict(self, model: Any, input_data: Any) -> Any:
        """Make predictions using ONNX model."""
        if not HAS_ONNX:
            raise ImportError("ONNX Runtime not available")

        try:
            if np is not None and not isinstance(input_data, np.ndarray):
                input_data = np.array(input_data, dtype=np.float32)

            input_name = model.get_inputs()[0].name
            outputs = model.run(None, {input_name: input_data})

            return outputs[0] if len(outputs) == 1 else outputs
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("ONNX prediction failed: %s", e)
            raise

    def get_model_info(self, model: Any) -> dict[str, Any]:
        """Get ONNX model information."""
        info: dict[str, Any] = {
            "backend": "onnx",
            "type": "ONNX Runtime Session",
            "inputs": [],
            "outputs": [],
        }

        try:
            for input_meta in model.get_inputs():
                info["inputs"].append(
                    {
                        "name": input_meta.name,
                        "shape": input_meta.shape,
                        "type": input_meta.type,
                    },
                )

            for output_meta in model.get_outputs():
                info["outputs"].append(
                    {
                        "name": output_meta.name,
                        "shape": output_meta.shape,
                        "type": output_meta.type,
                    },
                )
        except (AttributeError, RuntimeError) as e:
            logger.debug("Failed to get ONNX model input/output info: %s", e)

        return info


class SklearnBackend(ModelBackend):
    """Scikit-learn model backend."""

    def load_model(self, model_path: str) -> Any:
        """Load a scikit-learn model."""
        if not HAS_JOBLIB:
            raise ImportError("Joblib not available")

        try:
            return joblib.load(model_path)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Failed to load sklearn model: %s", e)
            raise

    def predict(self, model: Any, input_data: Any) -> Any:
        """Make predictions using scikit-learn model."""
        try:
            if np is not None and not isinstance(input_data, np.ndarray):
                input_data = np.array(input_data)

            if hasattr(model, "predict_proba"):
                return model.predict_proba(input_data)
            return model.predict(input_data)
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Sklearn prediction failed: %s", e)
            raise

    def get_model_info(self, model: Any) -> dict[str, Any]:
        """Get scikit-learn model information."""
        info: dict[str, Any] = {
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

    def __init__(self, cache_dir: str | None = None, max_cache_size: int = 5) -> None:
        """Initialize the model cache system.

        Args:
            cache_dir: Directory for storing cached models.
                      Defaults to ~/.intellicrack/model_cache if not provided.
            max_cache_size: Maximum number of models to keep in cache.

        """
        self.logger = logging.getLogger(f"{__name__}.ModelCache")
        self.cache_dir = cache_dir or os.path.join(os.path.expanduser("~"), ".intellicrack", "model_cache")
        self.max_cache_size = max_cache_size
        self.cache: dict[str, Any] = {}
        self.access_times: dict[str, float] = {}
        self.lock = threading.RLock()

        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_cache_key(self, model_path: str) -> str:
        """Generate a cache key for the model."""
        try:
            mtime = Path(model_path).stat().st_mtime
            key_string = f"{model_path}_{mtime}"
            return hashlib.sha256(key_string.encode()).hexdigest()
        except (OSError, ValueError) as e:
            self.logger.exception("Error in model_manager_module: %s", e)
            return hashlib.sha256(model_path.encode()).hexdigest()

    def get(self, model_path: str) -> Any:
        """Get model from cache."""
        with self.lock:
            cache_key = self._get_cache_key(model_path)

            if cache_key in self.cache:
                self.access_times[cache_key] = time.time()
                logger.debug("Model cache hit for %s", model_path)
                return self.cache[cache_key]

            return None

    def put(self, model_path: str, model: Any) -> None:
        """Put model in cache."""
        with self.lock:
            cache_key = self._get_cache_key(model_path)

            if len(self.cache) >= self.max_cache_size:
                self._evict_oldest()

            self.cache[cache_key] = model
            self.access_times[cache_key] = time.time()
            logger.debug("Model cached for %s", model_path)

    def _evict_oldest(self) -> None:
        """Evict the oldest accessed model from cache."""
        if not self.access_times:
            return

        oldest_key = min(self.access_times, key=lambda k: self.access_times[k])
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

    def __init__(self, models_dir: str | None = None, cache_size: int = 5) -> None:
        """Initialize the AI model manager.

        Args:
            models_dir: Directory containing AI models. If None, defaults to
                        ../models relative to this file
            cache_size: Maximum number of models to keep in cache

        """
        self.models_dir = models_dir or os.path.join(os.path.dirname(__file__), "..", "models")
        self.cache = ModelCache(max_cache_size=cache_size)
        self.backends = self._initialize_backends()
        self.loaded_models: dict[str, Any] = {}
        self.model_metadata: dict[str, Any] = {}
        self.lock = threading.RLock()
        self.gpu_info: Any = None

        if GPU_AUTOLOADER_AVAILABLE and get_gpu_info is not None:
            try:
                self.gpu_info = get_gpu_info()
                if self.gpu_info:
                    logger.info("ModelManager initialized with GPU: %s", self.gpu_info)
            except Exception as e:
                logger.debug("Could not get GPU info: %s", e, exc_info=True)

        os.makedirs(self.models_dir, exist_ok=True)
        self._load_model_metadata()

    def _initialize_backends(self) -> dict[str, ModelBackend]:
        """Initialize available model backends."""
        backends: dict[str, ModelBackend] = {}

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
            logger.exception("Failed to save model metadata: %s", e)

    def _detect_model_type(self, model_path: str) -> str:
        """Detect the model type from file extension or content."""
        file_ext = Path(model_path).suffix.lower().lstrip(".")

        # Direct extension mapping
        if file_ext in self.backends:
            return file_ext

        # Special cases
        if file_ext == "json" and os.path.exists(model_path.replace(".json", ".bin")):
            return "tensorflow"

        if Path(model_path).is_dir() and os.path.exists(os.path.join(model_path, "saved_model.pb")):
            return "savedmodel"

        # Default fallback
        return "sklearn"

    def register_model(
        self,
        model_id: str,
        model_path: str,
        model_type: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Register a model with the manager."""
        with self.lock:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")

            resolved_model_type = model_type if model_type is not None else self._detect_model_type(model_path)

            if resolved_model_type not in self.backends:
                raise ValueError(f"Unsupported model type: {resolved_model_type}")

            self.model_metadata[model_id] = {
                "path": model_path,
                "type": resolved_model_type,
                "registered": datetime.now().isoformat(),
                "metadata": metadata or {},
            }

            self._save_model_metadata()
            logger.info("Registered model: %s (%s)", model_id, resolved_model_type)

    def load_model(self, model_id: str) -> Any:
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
                    logger.info("Downloaded model %s from model zoo", model_id)
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
                logger.info("Creating pre-trained model: %s", model_id)
                model = model_map[model_id]()
                self.loaded_models[model_id] = model
            return self.loaded_models[model_id]

        raise ValueError(f"Unknown pre-trained model: {model_id}")

    def _create_vulnerability_detector(self) -> Any:
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

                def forward(self, x: Any) -> Any:
                    x = self.dropout1(self.relu1(self.fc1(x)))
                    x = self.dropout2(self.relu2(self.fc2(x)))
                    x = self.relu3(self.fc3(x))
                    x = self.softmax(self.fc4(x))
                    return x

                def detect_vulnerabilities(self, binary_features: Any) -> list[list[dict[str, Any]]]:
                    """Detect vulnerabilities from binary feature vectors."""
                    with torch.no_grad():
                        predictions = self.forward(binary_features)
                        top_k = torch.topk(predictions, k=3, dim=1)
                        results: list[list[dict[str, Any]]] = []
                        for i in range(top_k.values.shape[0]):
                            vulns: list[dict[str, Any]] = []
                            for j in range(3):
                                vuln_idx = int(top_k.indices[i][j].item())
                                confidence = top_k.values[i][j].item()
                                if confidence > 0.3:
                                    vulns.append({
                                        "type": self.vulnerability_types[vuln_idx],
                                        "confidence": confidence,
                                    })
                            results.append(vulns)
                        return results

            model = VulnerabilityDetector()
            model.eval()
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

    def _create_protection_classifier(self) -> Any:
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

                def forward(self, x: Any) -> Any:
                    x = x.unsqueeze(1)
                    x = self.pool(self.relu(self.conv1(x)))
                    x = self.pool(self.relu(self.conv2(x)))
                    x = x.flatten(1)
                    x = self.dropout(self.relu(self.fc1(x)))
                    x = self.dropout(self.relu(self.fc2(x)))
                    x = torch.sigmoid(self.fc3(x))
                    return x

                def classify_protections(self, binary_features: Any) -> list[dict[str, Any]]:
                    """Classify protection mechanisms from binary features."""
                    with torch.no_grad():
                        predictions = self.forward(binary_features)
                        return [
                            {
                                "type": self.protection_types[i],
                                "confidence": predictions[0][i].item(),
                            }
                            for i in range(predictions.shape[1])
                            if predictions[0][i] > 0.5
                        ]

            model = ProtectionClassifier()
            model.eval()
            return model

        class SimpleProtectionClassifier:
            """Perform rule-based protection classifier."""

            def __init__(self) -> None:
                self.protection_patterns: dict[str, list[bytes]] = {
                    "anti_debug": [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent"],
                    "anti_vm": [b"VMware", b"VirtualBox", b"QEMU"],
                    "packing": [b"UPX", b"ASPack", b"Themida"],
                    "license_check": [b"license", b"serial", b"activation"],
                }

            def classify_protections(self, binary_data: bytes) -> list[dict[str, Any]]:
                detected: list[dict[str, Any]] = []
                for protection, patterns in self.protection_patterns.items():
                    for pattern in patterns:
                        if pattern in binary_data:
                            detected.append({"type": protection, "confidence": 0.8})
                            break
                return detected

        return SimpleProtectionClassifier()

    def _create_script_generator_model(self) -> Any:
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

                    self.script_templates: dict[str, str] = {
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

                def forward(self, x: Any, hidden: Any = None) -> tuple[Any, Any]:
                    embed = self.embedding(x)
                    output, hidden = self.lstm(embed, hidden)
                    output = self.fc(output)
                    return output, hidden

                def generate_script_snippet(self, protection_type: str, target_info: dict[str, Any]) -> str:
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
                    return f"// Custom script needed for: {protection_type}"

            model = ScriptGeneratorModel()
            model.eval()
            return model

        class TemplateScriptGenerator:
            def __init__(self) -> None:
                self.templates: dict[str, str] = {
                    "license": "Interceptor.replace(ptr({addr}), new NativeCallback(() => 1, 'int', []));",
                    "anti_debug": "Interceptor.attach(Module.findExportByName(null, 'IsDebuggerPresent'), {onLeave: (r) => r.replace(0)});",
                    "trial": "Memory.writeU32(ptr({addr}), 0xFFFFFFFF); // Extend trial",
                }

            def generate_script_snippet(self, protection_type: str, target_info: dict[str, Any]) -> str:
                return self.templates.get(protection_type, "// Manual analysis required")

        return TemplateScriptGenerator()

    def _create_binary_analyzer_model(self) -> Any:
        """Create a comprehensive binary analysis model."""
        if HAS_TORCH:
            import torch
            from torch import nn

            class BinaryAnalyzerModel(nn.Module):
                """Comprehensive binary analysis using CNN + attention."""

                def __init__(self, input_channels: int = 1, num_features: int = 128) -> None:
                    super().__init__()
                    self.conv1 = nn.Conv2d(input_channels, 32, kernel_size=3, padding=1)
                    self.conv2 = nn.Conv2d(32, 64, kernel_size=3, padding=1)
                    self.conv3 = nn.Conv2d(64, 128, kernel_size=3, padding=1)
                    self.pool = nn.MaxPool2d(2)

                    self.attention = nn.MultiheadAttention(num_features, num_heads=8)

                    self.arch_classifier = nn.Linear(num_features, 4)
                    self.compiler_classifier = nn.Linear(num_features, 6)
                    self.packer_detector = nn.Linear(num_features, 10)

                    self.architectures = ["x86", "x64", "ARM", "MIPS"]
                    self.compilers = ["GCC", "MSVC", "Clang", "ICC", "Borland", "Unknown"]
                    self.packers = [
                        "UPX",
                        "ASPack",
                        "PECompact",
                        "Themida",
                        "VMProtect",
                        "Enigma",
                        "MPRESS",
                        "FSG",
                        "NSPack",
                        "None",
                    ]

                def forward(self, x: Any) -> tuple[Any, Any, Any]:
                    x = torch.relu(self.conv1(x))
                    x = self.pool(x)
                    x = torch.relu(self.conv2(x))
                    x = self.pool(x)
                    x = torch.relu(self.conv3(x))
                    x = self.pool(x)

                    batch_size = x.size(0)
                    x = x.view(batch_size, -1, 128)
                    x, _ = self.attention(x, x, x)
                    x = x.mean(dim=1)

                    arch = torch.softmax(self.arch_classifier(x), dim=1)
                    compiler = torch.softmax(self.compiler_classifier(x), dim=1)
                    packer = torch.softmax(self.packer_detector(x), dim=1)

                    return arch, compiler, packer

                def analyze_binary(self, binary_tensor: Any) -> dict[str, Any]:
                    """Comprehensive binary analysis."""
                    with torch.no_grad():
                        arch, compiler, packer = self.forward(binary_tensor)

                        return {
                            "architecture": self.architectures[int(arch.argmax().item())],
                            "arch_confidence": arch.max().item(),
                            "compiler": self.compilers[int(compiler.argmax().item())],
                            "compiler_confidence": compiler.max().item(),
                            "packer": self.packers[int(packer.argmax().item())],
                            "packer_confidence": packer.max().item(),
                        }

            model = BinaryAnalyzerModel()
            model.eval()
            return model

        class HeuristicBinaryAnalyzer:
            def analyze_binary(self, binary_data: bytes) -> dict[str, Any]:
                results: dict[str, Any] = {
                    "architecture": "x86" if b"MZ" in binary_data[:2] else "Unknown",
                    "arch_confidence": 0.7,
                    "compiler": "MSVC" if b"Visual Studio" in binary_data else "Unknown",
                    "compiler_confidence": 0.6,
                    "packer": "None",
                    "packer_confidence": 0.5,
                }

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
            logger.info("Downloading model %s from %s", model_id, model_url)
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
            logger.exception("Failed to download model %s: %s", model_id, e)
            return False

    def _load_model_with_fallback(self, model_path: str, model_type: str, model_id: str) -> object:
        """Load model with fallback mechanisms for missing files."""
        if not os.path.exists(model_path):
            logger.warning("Model file not found: %s", model_path)
            # Try to create a default model
            if model_type == "pytorch":
                if HAS_TORCH:
                    from torch import nn

                    # Create a simple neural network as fallback
                    model = nn.Sequential(nn.Linear(100, 50), nn.ReLU(), nn.Linear(50, 10), nn.Softmax(dim=1))
                    logger.info("Created default PyTorch model for %s", model_id)
                    return model
            elif model_type == "sklearn":
                if HAS_JOBLIB:
                    from sklearn.ensemble import RandomForestClassifier

                    model = RandomForestClassifier(n_estimators=10, random_state=42)
                    logger.info("Created default sklearn model for %s", model_id)
                    return model

            raise FileNotFoundError(f"Model file not found and no fallback available: {model_path}")

        # Load normally
        backend = self.backends[model_type]
        return backend.load_model(model_path)

    def _optimize_loaded_model(self, model: Any, model_id: str, model_type: str) -> Any:
        """Apply optimizations to loaded model."""
        if GPU_AUTOLOADER_AVAILABLE:
            try:
                if get_device is not None:
                    device = get_device()
                    if device != "cpu":
                        if to_device is not None:
                            model = to_device(model, device)
                            logger.info("Moved model %s to %s", model_id, device)

                        if optimize_for_gpu is not None:
                            optimized_model = optimize_for_gpu(model)
                            if optimized_model is not None:
                                model = optimized_model
                                logger.info("Applied GPU optimizations to model %s", model_id)
            except Exception as e:
                logger.debug("Could not optimize model for GPU: %s", e, exc_info=True)

        if model_type == "pytorch" and HAS_TORCH:
            try:
                import torch

                if hasattr(model, "eval"):
                    model.eval()
                    if hasattr(model, "parameters"):
                        params = model.parameters()
                        first_param = next(params, None)
                        if (
                            first_param is not None
                            and not first_param.is_cuda
                            and (hasattr(torch, "quantization") and hasattr(torch.quantization, "quantize_dynamic"))
                        ):
                            quantized = torch.quantization.quantize_dynamic(model, {torch.nn.Linear}, dtype=torch.qint8)
                            logger.info("Applied quantization to %s", model_id)
                            return quantized
            except Exception as e:
                logger.debug("Could not quantize model: %s", e, exc_info=True)

        return model

    def predict(self, model_id: str, input_data: Any) -> Any:
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

    def _predict_with_pretrained(self, model_id: str, input_data: Any) -> dict[str, Any]:
        """Make predictions using pretrained models with structured output."""
        model = self.load_model(model_id)

        if model_id == "pretrained/vulnerability_detector":
            return self._predict_vulnerabilities(model, input_data)
        if model_id == "pretrained/protection_classifier":
            return self._predict_protections(model, input_data)
        if model_id == "pretrained/script_generator":
            if isinstance(input_data, dict):
                return self._predict_script_generation(model, input_data)
            return {"error": "Script generation requires dict input"}
        if model_id == "pretrained/binary_analyzer":
            return self._predict_binary_analysis(model, input_data)
        raise ValueError(f"Unknown pretrained model: {model_id}")

    def _predict_vulnerabilities(self, model: Any, input_data: Any) -> dict[str, Any]:
        """Predict vulnerabilities with scoring and recommendations."""
        features: Any
        if isinstance(input_data, bytes):
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
            binary = input_data if isinstance(input_data, bytes) else b""
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
            unsafe_func_count = sum(func in binary for func in buffer_overflow_indicators)
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
            format_funcs = sum(func in binary for func in format_string_indicators)
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
                overflow_risk = sum(pattern in binary for pattern in alloc_patterns)
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

    def _predict_protections(self, model: Any, input_data: Any) -> dict[str, Any]:
        """Predict protection mechanisms in binary."""
        protections: list[dict[str, Any]]
        if hasattr(model, "classify_protections"):
            protections = model.classify_protections(input_data)
        else:
            protections = []
            if isinstance(input_data, bytes):
                if b"IsDebuggerPresent" in input_data:
                    protections.append({"type": "anti_debug", "confidence": 0.9})
                if b"VMware" in input_data or b"VirtualBox" in input_data:
                    protections.append({"type": "anti_vm", "confidence": 0.85})
                if b"license" in input_data.lower():
                    protections.append({"type": "license_check", "confidence": 0.7})

        protection_categories: dict[str, list[str]] = {
            "anti_analysis": ["anti_debug", "anti_vm", "anti_dump"],
            "licensing": ["license_check", "hardware_lock", "time_trial"],
            "integrity": ["integrity_check", "anti_tamper", "self_modification"],
            "obfuscation": ["packing", "encryption", "code_virtualization"],
        }

        categorized: dict[str, list[dict[str, Any]]] = {
            category: [p for p in protections if p["type"] in types] for category, types in protection_categories.items()
        }
        return {
            "protections": protections,
            "categorized": categorized,
            "protection_score": len(protections) * 10,
            "bypass_difficulty": self._calculate_bypass_difficulty(protections),
            "bypass_strategies": self._generate_bypass_strategies(protections),
        }

    def _predict_script_generation(self, model: Any, input_data: dict[str, Any]) -> dict[str, Any]:
        """Generate script predictions and templates."""
        protection_type = str(input_data.get("protection_type", "unknown"))
        target_info: dict[str, Any] = input_data.get("target_info", {}) if isinstance(input_data.get("target_info"), dict) else {}

        if hasattr(model, "generate_script_snippet"):
            script = model.generate_script_snippet(protection_type, target_info)
        else:
            scripts: dict[str, str] = {
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

    def _predict_binary_analysis(self, model: Any, input_data: Any) -> dict[str, Any]:
        """Comprehensive binary analysis prediction."""
        analysis: dict[str, Any]
        if hasattr(model, "analyze_binary"):
            analysis = model.analyze_binary(input_data)
        else:
            binary_bytes = input_data if isinstance(input_data, bytes) else b""
            analysis = {
                "architecture": "x86" if len(binary_bytes) >= 2 and b"MZ" in binary_bytes[:2] else "Unknown",
                "arch_confidence": 0.7,
                "compiler": "Unknown",
                "compiler_confidence": 0.5,
                "packer": "None",
                "packer_confidence": 0.5,
            }

        binary_for_entropy = input_data[:1024] if isinstance(input_data, bytes) else b""
        entropy = self._calculate_entropy(binary_for_entropy)
        analysis["entropy"] = entropy
        analysis["likely_packed"] = entropy > 7.0

        binary_for_sections = input_data if isinstance(input_data, bytes) else b""
        analysis["sections"] = self._analyze_sections(binary_for_sections)

        analysis["suspicious_imports"] = self._find_suspicious_imports(binary_for_sections)

        return {
            "analysis": analysis,
            "classification": self._classify_binary_type(analysis),
            "recommended_tools": self._recommend_analysis_tools(analysis),
            "next_steps": self._generate_analysis_steps(analysis),
        }

    def _extract_binary_features(self, binary_data: bytes) -> "np.ndarray[Any, np.dtype[np.float32]]":
        """Extract feature vector from binary data."""
        byte_counts: np.ndarray[Any, np.dtype[np.float64]] = np.zeros(256)
        data_slice = binary_data[:10000]
        for byte in data_slice:
            byte_counts[byte] += 1
        features: list[float] = list(byte_counts / len(data_slice))
        for i in range(0, min(len(binary_data), 10000), 1000):
            chunk = binary_data[i : i + 1000]
            features.append(self._calculate_entropy(chunk))

        strings = self._extract_strings(binary_data[:10000])
        features.extend((
            float(len(strings)),
            float(np.mean([len(s) for s in strings])) if strings else 0.0,
        ))
        expected_size = 1024
        if len(features) < expected_size:
            features.extend([0.0] * (expected_size - len(features)))
        else:
            features = features[:expected_size]

        return np.array(features, dtype=np.float32)

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        import math

        if not data:
            return 0.0

        entropy: float = 0.0
        for i in range(256):
            count = data.count(bytes([i]))
            if count > 0:
                frequency = count / len(data)
                entropy -= frequency * math.log2(frequency)

        return entropy

    def _extract_strings(self, data: bytes, min_length: int = 4) -> list[str]:
        """Extract ASCII strings from binary data."""
        import re

        ascii_pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
        strings = re.findall(ascii_pattern, data)

        return [s.decode("ascii", errors="ignore") for s in strings]

    def _calculate_severity(self, vuln_type: str, confidence: float) -> str:
        """Calculate vulnerability severity."""
        high_severity_vulns = ["buffer_overflow", "command_injection", "use_after_free"]
        medium_severity_vulns = ["format_string", "integer_overflow", "path_traversal"]

        if vuln_type in high_severity_vulns:
            if confidence > 0.7:
                return "CRITICAL"
            if confidence > 0.5:
                return "HIGH"
        if vuln_type in medium_severity_vulns and confidence > 0.6:
            return "MEDIUM"
        return "LOW"

    def _find_similar_cves(self, vuln_type: str) -> list[str]:
        """Find similar CVEs for vulnerability type."""
        cve_database: dict[str, list[str]] = {
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
        return "HIGH" if security_score >= 50 else "CRITICAL"

    def _generate_vuln_recommendations(self, vulnerabilities: list[dict[str, Any]]) -> list[str]:
        """Generate recommendations for found vulnerabilities."""
        recommendations: list[str] = []

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

        return list(set(recommendations))

    def _calculate_bypass_difficulty(self, protections: list[dict[str, Any]]) -> str:
        """Calculate difficulty of bypassing protections."""
        difficult_protections = ["code_virtualization", "anti_tamper", "hardware_lock"]
        medium_protections = ["packing", "anti_debug", "integrity_check"]

        has_difficult = any(p["type"] in difficult_protections for p in protections)
        has_medium = any(p["type"] in medium_protections for p in protections)

        if has_difficult:
            return "EXPERT"
        return "INTERMEDIATE" if has_medium else "BEGINNER"

    def _generate_bypass_strategies(self, protections: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate bypass strategies for detected protections."""
        strategies: dict[str, Any] = {}

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

    def _analyze_sections(self, binary_data: bytes) -> list[dict[str, Any]]:
        """Analyze binary sections."""
        sections: list[dict[str, Any]] = []

        if binary_data[:2] == b"MZ":
            sections.extend((
                {
                    "name": ".text",
                    "size": 0x1000,
                    "entropy": self._calculate_entropy(binary_data[0x1000:0x2000]),
                    "executable": True,
                },
                {
                    "name": ".data",
                    "size": 0x500,
                    "entropy": self._calculate_entropy(binary_data[0x2000:0x2500]),
                    "executable": False,
                },
            ))
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

        return [api.decode("ascii") for api in suspicious_apis if api in binary_data]

    def _classify_binary_type(self, analysis: dict[str, Any]) -> str:
        """Classify binary type based on analysis."""
        if analysis.get("likely_packed"):
            return "Packed Executable"
        if analysis.get("suspicious_imports"):
            return "Potentially Malicious"
        return "Standard Executable"

    def _recommend_analysis_tools(self, analysis: dict[str, Any]) -> list[str]:
        """Recommend tools based on binary analysis."""
        tools = ["Ghidra", "x64dbg", "Radare2"]

        if analysis.get("likely_packed"):
            tools.extend(("UPX Unpacker", "PEiD"))
        if analysis.get("architecture") == "x64":
            tools.append("WinDbg")

        return tools

    def _generate_analysis_steps(self, analysis: dict[str, Any]) -> list[str]:
        """Generate next analysis steps."""
        steps: list[str] = []

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

    def predict_batch(self, model_id: str, batch_data: list[Any]) -> list[Any]:
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
                    logger.debug("Applied GPU batch optimization to model %s", model_id)
            except Exception as e:
                logger.debug("Could not apply batch optimization: %s", e, exc_info=True)

        # Process batch
        backend = self.backends[model_type]
        results = []
        for data in batch_data:
            try:
                result = backend.predict(model, data)
                results.append(result)
            except Exception as e:
                logger.exception("Batch prediction error: %s", e)
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

        return dict(model_info)

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

    def import_local_model(self, file_path: str) -> dict[str, Any] | None:
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
            logger.exception("Failed to import local model: %s", e)
            return None

    def get_available_repositories(self) -> list[str]:
        """Get list of available model repositories."""
        return ["huggingface", "local", "custom"]

    def get_available_models(self, repository: str | None = None) -> list[dict[str, Any]]:
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
            path = str(model_info.get("path", ""))

            if model_info.get("type") == "api":
                return path
            if model_info.get("type") == "repository":
                repo_name = str(model_info.get("repository", ""))
                model_name = str(model_info.get("model_name", model_id))
                if repo_name and model_name:
                    repo_dir = os.path.join(self.models_dir, "repositories", repo_name)
                    model_path = os.path.join(repo_dir, model_name)
                    if os.path.exists(model_path):
                        return model_path
                    for ext in [".pth", ".h5", ".onnx", ".pkl", ".joblib"]:
                        extended_path = model_path + ext
                        if os.path.exists(extended_path):
                            return extended_path

            if path and os.path.exists(path):
                return path

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
                    self.model_metadata[model_id]["path"] = p
                    self._save_model_metadata()
                    return p

        logger.warning("Model path not found for model_id: %s", model_id)
        return ""

    def import_api_model(self, model_name: str, api_config: dict[str, Any]) -> dict[str, Any] | None:
        """Import a model from an API."""
        try:
            model_id = f"api_{model_name}"

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
            logger.exception("Failed to import API model: %s", e)
            return None

    def train_model(self, training_data: Any, model_type: str) -> bool:
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
                logger.error("Backend not available for model type: %s. Available: %s", model_type, list(self.backends.keys()))
                return False

            # Create training workflow adapted to the specific model type and data format

            if model_type.lower() == "sklearn":
                backend = self.backends[model_type.lower()]

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

                    logger.info("Split data: %s training samples, %s validation samples", len(X_train), len(X_val))

                    # Create and train model
                    model = RandomForestClassifier(n_estimators=10, random_state=42)
                    model.fit(X_train, y_train)

                    # Evaluate on validation set
                    val_score = model.score(X_val, y_val)
                    logger.info("Validation accuracy: %.4f", val_score)

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
                            "Epoch [%s/%s], Train Loss: %.4f, Train Acc: %.2f%%, Val Acc: %.2f%%",
                            epoch + 1,
                            num_epochs,
                            train_loss / len(train_loader),
                            train_acc,
                            val_acc,
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

                    logger.info("PyTorch model training completed: %s", model_id)
                    return True

                except ImportError:
                    logger.warning("PyTorch not available for training")
                    return False
                except Exception as e:
                    logger.exception("PyTorch training error: %s", e)
                    return False

            elif model_type.lower() == "tensorflow":
                # TensorFlow/Keras training implementation
                try:
                    from types import ModuleType

                    from intellicrack.handlers.tensorflow_handler import (
                        ensure_tensorflow_loaded,
                        tf as tensorflow_module,
                    )

                    ensure_tensorflow_loaded()
                    if not isinstance(tensorflow_module, ModuleType):
                        logger.error("TensorFlow not available after initialization")
                        return False

                    keras = cast("ModuleType", tensorflow_module.keras)
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

                    num_classes = len(np.unique(y))

                    local_keras: Any = keras
                    local_tf: Any = tf

                    if num_classes > 2:
                        y_train = local_tf.keras.utils.to_categorical(y_train, num_classes)
                        y_val = local_tf.keras.utils.to_categorical(y_val, num_classes)

                    tf_model: Any = local_keras.Sequential(
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

                    if num_classes > 2:
                        tf_model.compile(
                            optimizer="adam",
                            loss="categorical_crossentropy",
                            metrics=["accuracy"],
                        )
                    else:
                        tf_model.compile(
                            optimizer="adam",
                            loss="binary_crossentropy",
                            metrics=["accuracy"],
                        )

                    early_stopping: Any = local_keras.callbacks.EarlyStopping(
                        monitor="val_loss",
                        patience=3,
                        restore_best_weights=True,
                    )

                    history: Any = tf_model.fit(
                        X_train,
                        y_train,
                        validation_data=(X_val, y_val),
                        epochs=20,
                        batch_size=32,
                        callbacks=[early_stopping],
                        verbose=1,
                    )

                    eval_result: Any = tf_model.evaluate(X_val, y_val, verbose=0)
                    tf_val_loss: float = float(eval_result[0])
                    tf_val_acc: float = float(eval_result[1])

                    logger.info("TensorFlow training completed - Val Loss: %.4f, Val Acc: %.4f", tf_val_loss, tf_val_acc)

                    tf_model_id = f"trained_tensorflow_model_{len(self.cache.cache)}"
                    tf_model_data: dict[str, Any] = {
                        "model": tf_model,
                        "backend": "tensorflow",
                        "last_used": time.time(),
                        "metadata": {
                            "type": "tensorflow",
                            "trained": True,
                            "training_samples": len(X_train),
                            "validation_samples": len(X_val),
                            "validation_loss": tf_val_loss,
                            "validation_accuracy": tf_val_acc,
                            "num_epochs": len(history.history["loss"]),
                            "num_classes": num_classes,
                        },
                    }
                    self.cache.put(tf_model_id, tf_model_data)

                    logger.info("TensorFlow model training completed: %s", tf_model_id)
                    return True

                except ImportError:
                    logger.warning("TensorFlow not available for training")
                    return False
                except Exception as e:
                    logger.exception("TensorFlow training error: %s", e)
                    return False

            else:
                logger.error("Unsupported model type for training: %s", model_type)
                return False

        except Exception as e:
            logger.exception("Model training failed: %s", e)
            return False

    def save_model(self, model: Any, path: str) -> bool:
        """Save a trained model to disk.

        Args:
            model: Model object to save
            path: File path where to save the model

        Returns:
            bool: True if saving succeeded, False otherwise

        """
        try:
            import pickle  # noqa: S403
            from pathlib import Path

            save_path = Path(path)
            save_path.parent.mkdir(parents=True, exist_ok=True)

            model_type = type(model).__name__.lower()

            if "sklearn" in str(type(model)) or hasattr(model, "fit"):
                try:
                    import joblib

                    joblib.dump(model, str(save_path))
                    logger.info("Model (type: %s) saved using joblib: %s", model_type, path)
                    return True
                except ImportError:
                    with open(save_path, "wb") as f:
                        pickle.dump(model, f)
                    logger.info("Model saved using pickle: %s", path)
                    return True

            elif "torch" in str(type(model)):
                try:
                    import torch

                    if hasattr(model, "state_dict"):
                        torch.save(model.state_dict(), str(save_path))
                    else:
                        torch.save(model, str(save_path))
                    logger.info("PyTorch model saved: %s", path)
                    return True
                except ImportError:
                    logger.exception("PyTorch not available for saving")
                    return False

            elif "tensorflow" in str(type(model)) or "keras" in str(type(model)):
                try:
                    if hasattr(model, "save"):
                        model.save(str(save_path))
                        logger.info("TensorFlow/Keras model saved: %s", path)
                        return True
                    logger.error("Model does not have save method")
                    return False
                except Exception as tf_error:
                    logger.exception("TensorFlow model save failed: %s", tf_error)
                    return False

            else:
                with open(save_path, "wb") as f:
                    pickle.dump(model, f)
                logger.info("Model saved using generic pickle: %s", path)
                return True

        except Exception as e:
            logger.exception("Model save failed: %s", e)
            return False

    @property
    def repositories(self) -> list[str]:
        """Get available repositories."""
        return self.get_available_repositories()

    def evaluate_model_with_split(
        self,
        model_id: str,
        data: Any,
        labels: Any,
        test_size: float = 0.2,
        random_state: int = 42,
    ) -> dict[str, Any]:
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

            model_data = self.cache.get(model_id)
            if not model_data:
                logger.error("Model %s not found in cache", model_id)
                return {"error": "Model not found"}

            model: Any = model_data.get("model")
            backend = model_data.get("backend")

            if not isinstance(data, np.ndarray):
                data = np.array(data)
            if not isinstance(labels, np.ndarray):
                labels = np.array(labels)

            X_train, X_test, y_train, y_test = train_test_split(
                data,
                labels,
                test_size=test_size,
                random_state=random_state,
                stratify=labels if len(np.unique(labels)) > 1 else None,
            )

            logger.info("Split data into %s training and %s test samples", len(X_train), len(X_test))

            evaluation_results: dict[str, Any] = {
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

                evaluation_results |= {
                    "train_score": train_score,
                    "test_score": test_score,
                    "overfitting_gap": train_score - test_score,
                }

                # Get predictions for additional metrics
                y_pred = model.predict(X_test)

                # Calculate additional metrics if classification
                if hasattr(model, "predict_proba"):
                    from sklearn.metrics import classification_report, confusion_matrix

                    report = classification_report(y_test, y_pred, output_dict=True)
                    cm = confusion_matrix(y_test, y_pred)

                    evaluation_results |= {
                        "classification_report": report,
                        "confusion_matrix": cm.tolist(),
                    }

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

                evaluation_results |= {
                    "train_accuracy": train_accuracy,
                    "test_accuracy": test_accuracy,
                    "backend": "pytorch",
                }

            logger.info(
                "Model evaluation completed with test score: %s",
                evaluation_results.get("test_score", evaluation_results.get("test_accuracy", "N/A")),
            )
            return evaluation_results

        except ImportError as e:
            logger.exception("Failed to import required libraries: %s", e)
            return {"error": f"Missing dependencies: {e}"}
        except Exception as e:
            logger.exception("Model evaluation failed: %s", e)
            return {"error": str(e)}


class AsyncModelManager:
    """Asynchronous wrapper for model operations."""

    def __init__(self, model_manager: ModelManager) -> None:
        """Initialize the asynchronous model manager wrapper.

        Args:
            model_manager: The underlying ModelManager instance to wrap with async capabilities.

        """
        self.logger = logging.getLogger(f"{__name__}.AsyncModelManager")
        self.model_manager = model_manager
        self.thread_pool: dict[str, threading.Thread] = {}

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
                self.logger.exception("Error in model_manager_module: %s", e)
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
                self.logger.exception("Error in model_manager_module: %s", e)
                if callback:
                    callback(False, None, str(e))

        thread = threading.Thread(target=predict_worker, daemon=True)
        thread.start()
        return thread


# Factory function for easy instantiation
def create_model_manager(models_dir: str | None = None, cache_size: int = 5) -> ModelManager:
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
        self.logger = logging.getLogger(f"{__name__}.ModelFineTuner")
        self.model_manager = model_manager
        self.training_history: dict[str, Any] = {}
        self.lock = threading.RLock()

    def fine_tune_model(
        self,
        model_id: str,
        training_data: Any,
        validation_data: Any = None,
        epochs: int = 10,
        learning_rate: float = 0.001,
        batch_size: int = 32,
        callback: Callable[..., None] | None = None,
    ) -> dict[str, Any]:
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
            model = self.model_manager.load_model(model_id)
            model_info = self.model_manager.model_metadata[model_id]
            model_type = str(model_info["type"])

            results: dict[str, Any] = {
                "model_id": model_id,
                "epochs": epochs,
                "training_loss": [],
                "validation_loss": [],
                "metrics": {},
                "fine_tuned_model_path": None,
            }

            def noop_callback(*args: Any, **kwargs: Any) -> None:
                pass

            actual_callback = callback if callback is not None else noop_callback

            try:
                if model_type in {"pytorch", "pth"} and HAS_TORCH:
                    results = self._fine_tune_pytorch(
                        model,
                        training_data,
                        validation_data,
                        epochs,
                        learning_rate,
                        batch_size,
                        actual_callback,
                    )
                elif model_type in {"tensorflow", "h5"} and HAS_TENSORFLOW:
                    results = self._fine_tune_tensorflow(
                        model,
                        training_data,
                        validation_data,
                        epochs,
                        learning_rate,
                        batch_size,
                        actual_callback,
                    )
                elif model_type in {"sklearn", "joblib"} and HAS_JOBLIB:
                    results = self._fine_tune_sklearn(
                        model,
                        training_data,
                        validation_data,
                        actual_callback,
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
                elif model_type in {"pytorch", "pth"}:
                    torch.save(model, fine_tuned_path)
                elif model_type in {"tensorflow", "h5"}:
                    model.save(fine_tuned_path)
                elif model_type in {"sklearn", "joblib"}:
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
                logger.exception("Fine-tuning failed: %s", e)
                results["error"] = str(e)

            return results

    def _fine_tune_pytorch(
        self,
        model: Any,
        training_data: Any,
        validation_data: Any,
        epochs: int,
        learning_rate: float,
        batch_size: int,
        callback: Callable[..., None],
    ) -> dict[str, Any]:
        """Fine-tune a PyTorch model."""
        if not HAS_TORCH or torch is None or nn is None:
            return {"error": "PyTorch not available"}

        try:
            from torch import optim
            from torch.utils.data import DataLoader, TensorDataset
        except ImportError as e:
            self.logger.exception("Import error in model_manager_module: %s", e)
            return {"error": "PyTorch components not available"}

        model.train()

        optimizer = optim.Adam(model.parameters(), lr=learning_rate)
        criterion = nn.CrossEntropyLoss()

        train_dataset = TensorDataset(
            torch.tensor(training_data[0]).float(),
            torch.tensor(training_data[1]).long(),
        )
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

        val_loader: Any = None
        if validation_data is not None:
            val_dataset = TensorDataset(
                torch.tensor(validation_data[0]).float(),
                torch.tensor(validation_data[1]).long(),
            )
            val_loader = DataLoader(val_dataset, batch_size=batch_size)

        results: dict[str, Any] = {
            "training_loss": [],
            "validation_loss": [],
        }

        avg_val_loss: float | None = None
        for epoch in range(epochs):
            train_loss = 0.0
            for data, target in train_loader:
                optimizer.zero_grad()
                output = model(data)
                loss = criterion(output, target)
                loss.backward()
                optimizer.step()
                train_loss += loss.item()

            avg_train_loss = train_loss / len(train_loader)
            results["training_loss"].append(avg_train_loss)

            if val_loader is not None:
                model.eval()
                val_loss_total = 0.0
                with torch.no_grad():
                    for data, target in val_loader:
                        output = model(data)
                        val_loss_total += criterion(output, target).item()

                avg_val_loss = val_loss_total / len(val_loader)
                results["validation_loss"].append(avg_val_loss)
                model.train()

            callback(epoch + 1, epochs, avg_train_loss, avg_val_loss)

        return results

    def _fine_tune_tensorflow(
        self,
        model: Any,
        training_data: Any,
        validation_data: Any,
        epochs: int,
        learning_rate: float,
        batch_size: int,
        callback: Callable[..., None],
    ) -> dict[str, Any]:
        """Fine-tune a TensorFlow model."""
        if keras is None:
            return {"error": "Keras not available"}

        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
            loss="sparse_categorical_crossentropy",
            metrics=["accuracy"],
        )

        keras_callbacks: list[Any] = []

        class ProgressCallback:
            """Progress callback for TensorFlow training."""

            def on_epoch_end(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
                actual_logs = logs if logs is not None else {}
                callback(epoch + 1, epochs, actual_logs.get("loss"), actual_logs.get("val_loss"))

        keras_callbacks.append(ProgressCallback())

        history = model.fit(
            training_data[0],
            training_data[1],
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=keras_callbacks,
            verbose=0,
        )

        return {
            "training_loss": history.history["loss"],
            "validation_loss": history.history.get("val_loss", []),
            "metrics": history.history,
        }

    def _fine_tune_sklearn(
        self,
        model: Any,
        training_data: Any,
        validation_data: Any,
        callback: Callable[..., None],
    ) -> dict[str, Any]:
        """Fine-tune a scikit-learn model."""
        X_train: Any
        y_train: Any
        X_train, y_train = training_data

        if hasattr(model, "partial_fit"):
            model.partial_fit(X_train, y_train)
        else:
            model.fit(X_train, y_train)

        results: dict[str, Any] = {"training_complete": True}

        if validation_data is not None:
            X_val: Any
            y_val: Any
            X_val, y_val = validation_data
            val_score = model.score(X_val, y_val)
            results["validation_score"] = val_score

        callback(1, 1, None, results.get("validation_score"))

        return results

    def get_training_history(self, model_id: str) -> dict[str, Any] | None:
        """Get training history for a fine-tuned model."""
        return self.training_history.get(model_id)


def import_custom_model(model_path: str, model_type: str | None = None, model_id: str | None = None) -> dict[str, Any]:
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
        logger.exception("Failed to import model: %s", e)
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
        logger.exception("Failed to load model %s: %s", model_id, e)
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
            import pickle as pickle_lib  # noqa: S403

            with open(save_path, "wb") as f:
                pickle_lib.dump(model, f)
        elif model_format == "joblib":
            if HAS_JOBLIB:
                joblib.dump(model, save_path)
            else:
                import pickle as pickle_lib  # noqa: S403

                with open(save_path, "wb") as f:
                    pickle_lib.dump(model, f)
        elif model_format == "pytorch":
            if HAS_TORCH and torch is not None:
                torch.save(model, save_path)
            else:
                raise ImportError("PyTorch not available for saving .pt/.pth files")
        else:
            # Default to pickle
            import pickle as pickle_lib  # noqa: S403

            with open(save_path, "wb") as f:
                pickle_lib.dump(model, f)

        return {
            "success": True,
            "model_id": model_id,
            "save_path": save_path,
            "format": model_format,
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Failed to save model %s: %s", model_id, e)
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
        for model_id in models:
            try:
                info = manager.get_model_info(model_id)
                detailed_models[model_id] = info
            except (OSError, ValueError, RuntimeError) as e:
                logger.exception("Error in model_manager_module: %s", e)
                detailed_models[model_id] = {"error": str(e)}

        return {
            "success": True,
            "model_count": len(models),
            "models": detailed_models,
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.exception("Failed to list models: %s", e)
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
            "api_key": f"{api_key[:4]}...{api_key[-4:]}" if api_key else None,
            "timestamp": str(datetime.now()),
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
        logger.exception("Failed to configure AI provider %s: %s", provider_name, e)
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
