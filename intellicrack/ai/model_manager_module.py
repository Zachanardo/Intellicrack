"""
AI Model Manager Module for Intellicrack. 

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import hashlib
import json
import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Import common availability flags
from ..utils.core.common_imports import HAS_NUMPY, HAS_TORCH

if HAS_NUMPY:
    import numpy as np
else:
    np = None

if HAS_TORCH:
    import torch  # pylint: disable=import-error
    import torch.nn as nn  # pylint: disable=import-error
else:
    torch = None
    nn = None

try:
    import tensorflow as tf
    HAS_TENSORFLOW = True
except ImportError:
    tf = None
    HAS_TENSORFLOW = False

try:
    import onnx
    import onnxruntime as ort
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

logger = logging.getLogger(__name__)


class ModelBackend(ABC):
    """Abstract base class for AI model backends."""

    @abstractmethod
    def load_model(self, model_path: str) -> Any:
        """Load a model from the given path."""
        pass

    @abstractmethod
    def predict(self, model: Any, input_data: Any) -> Any:
        """Make predictions using the model."""
        pass

    @abstractmethod
    def get_model_info(self, model: Any) -> Dict[str, Any]:
        """Get information about the model."""
        pass


class PyTorchBackend(ModelBackend):
    """PyTorch model backend."""

    def load_model(self, model_path: str) -> Any:
        """Load a PyTorch model."""
        if not HAS_TORCH or torch is None:
            raise ImportError("PyTorch not available")

        try:
            model = torch.load(model_path, map_location='cpu')
            if hasattr(model, 'eval'):
                model.eval()
            return model
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load PyTorch model: %s", e)
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

            return output.numpy() if hasattr(output, 'numpy') else output
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("PyTorch prediction failed: %s", e)
            raise

    def get_model_info(self, model: Any) -> Dict[str, Any]:
        """Get PyTorch model information."""
        info = {
            'backend': 'pytorch',
            'type': type(model).__name__,
            'parameters': 0
        }

        if hasattr(model, 'parameters'):
            try:
                info['parameters'] = sum(_p.numel() for _p in model.parameters())
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
            model = tf.keras.models.load_model(model_path)  # pylint: disable=no-member
            return model
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load TensorFlow model: %s", e)
            raise

    def predict(self, model: Any, input_data: Any) -> Any:
        """Make predictions using TensorFlow model."""
        if not HAS_TENSORFLOW:
            raise ImportError("TensorFlow not available")

        try:
            if not isinstance(input_data, np.ndarray):
                input_data = np.array(input_data)

            predictions = model.predict(input_data)
            return predictions
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("TensorFlow prediction failed: %s", e)
            raise

    def get_model_info(self, model: Any) -> Dict[str, Any]:
        """Get TensorFlow model information."""
        info = {
            'backend': 'tensorflow',
            'type': type(model).__name__,
            'parameters': 0
        }

        if hasattr(model, 'count_params'):
            try:
                info['parameters'] = model.count_params()
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
            session = ort.InferenceSession(model_path)
            return session
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load ONNX model: %s", e)
            raise

    def predict(self, model: Any, input_data: Any) -> Any:
        """Make predictions using ONNX model."""
        if not HAS_ONNX:
            raise ImportError("ONNX Runtime not available")

        try:
            if not isinstance(input_data, np.ndarray):
                input_data = np.array(input_data, dtype=np.float32)

            input_name = model.get_inputs()[0].name
            outputs = model.run(None, {input_name: input_data})

            return outputs[0] if len(outputs) == 1 else outputs
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("ONNX prediction failed: %s", e)
            raise

    def get_model_info(self, model: Any) -> Dict[str, Any]:
        """Get ONNX model information."""
        info = {
            'backend': 'onnx',
            'type': 'ONNX Runtime Session',
            'inputs': [],
            'outputs': []
        }

        try:
            for _input_meta in model.get_inputs():
                info['inputs'].append({
                    'name': _input_meta.name,
                    'shape': _input_meta.shape,
                    'type': _input_meta.type
                })

            for _output_meta in model.get_outputs():
                info['outputs'].append({
                    'name': _output_meta.name,
                    'shape': _output_meta.shape,
                    'type': _output_meta.type
                })
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
            model = joblib.load(model_path)
            return model
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load sklearn model: %s", e)
            raise

    def predict(self, model: Any, input_data: Any) -> Any:
        """Make predictions using scikit-learn model."""
        try:
            if not isinstance(input_data, np.ndarray):
                input_data = np.array(input_data)

            if hasattr(model, 'predict_proba'):
                return model.predict_proba(input_data)
            else:
                return model.predict(input_data)
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Sklearn prediction failed: %s", e)
            raise

    def get_model_info(self, model: Any) -> Dict[str, Any]:
        """Get scikit-learn model information."""
        info = {
            'backend': 'sklearn',
            'type': type(model).__name__
        }

        if hasattr(model, 'feature_importances_'):
            info['has_feature_importance'] = True

        if hasattr(model, 'classes_'):
            info['classes'] = len(model.classes_)

        return info


class ModelCache:
    """Model caching system for efficient model management."""

    def __init__(self, cache_dir: str = None, max_cache_size: int = 5):
        self.cache_dir = cache_dir or os.path.join(os.path.expanduser('~'), '.intellicrack', 'model_cache')
        self.max_cache_size = max_cache_size
        self.cache = {}
        self.access_times = {}
        self.lock = threading.RLock()

        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_cache_key(self, model_path: str) -> str:
        """Generate a cache key for the model."""
        # Use file path and modification time for cache key
        try:
            mtime = os.path.getmtime(model_path)
            key_string = f"{model_path}_{mtime}"
            return hashlib.sha256(key_string.encode()).hexdigest()
        except (OSError, ValueError):
            return hashlib.sha256(model_path.encode()).hexdigest()

    def get(self, model_path: str) -> Optional[Any]:
        """Get model from cache."""
        with self.lock:
            cache_key = self._get_cache_key(model_path)

            if cache_key in self.cache:
                self.access_times[cache_key] = time.time()
                logger.debug("Model cache hit for %s", model_path)
                return self.cache[cache_key]

            return None

    def put(self, model_path: str, model: Any):
        """Put model in cache."""
        with self.lock:
            cache_key = self._get_cache_key(model_path)

            # Remove oldest items if cache is full
            if len(self.cache) >= self.max_cache_size:
                self._evict_oldest()

            self.cache[cache_key] = model
            self.access_times[cache_key] = time.time()
            logger.debug("Model cached for %s", model_path)

    def _evict_oldest(self):
        """Evict the oldest accessed model from cache."""
        if not self.access_times:
            return

        oldest_key = min(self.access_times, key=self.access_times.get)
        del self.cache[oldest_key]
        del self.access_times[oldest_key]
        logger.debug("Evicted model from cache: %s", oldest_key)

    def clear(self):
        """Clear the cache."""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
            logger.info("Model cache cleared")

    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            return {
                'size': len(self.cache),
                'max_size': self.max_cache_size,
                'cache_dir': self.cache_dir,
                'cached_models': list(self.cache.keys())
            }


class ModelManager:
    """Comprehensive AI model manager for Intellicrack."""

    def __init__(self, models_dir: str = None, cache_size: int = 5):
        self.models_dir = models_dir or os.path.join(os.path.dirname(__file__), '..', '..', 'models')
        self.cache = ModelCache(max_cache_size=cache_size)
        self.backends = self._initialize_backends()
        self.loaded_models = {}
        self.model_metadata = {}
        self.lock = threading.RLock()

        os.makedirs(self.models_dir, exist_ok=True)
        self._load_model_metadata()

    def _initialize_backends(self) -> Dict[str, ModelBackend]:
        """Initialize available model backends."""
        backends = {}

        if HAS_TORCH:
            backends['pytorch'] = PyTorchBackend()
            backends['pth'] = PyTorchBackend()

        if HAS_TENSORFLOW:
            backends['tensorflow'] = TensorFlowBackend()
            backends['h5'] = TensorFlowBackend()
            backends['savedmodel'] = TensorFlowBackend()

        if HAS_ONNX:
            backends['onnx'] = ONNXBackend()

        if HAS_JOBLIB:
            backends['sklearn'] = SklearnBackend()
            backends['joblib'] = SklearnBackend()
            backends['pkl'] = SklearnBackend()

        return backends

    def _load_model_metadata(self):
        """Load model metadata from disk."""
        metadata_file = os.path.join(self.models_dir, 'model_metadata.json')

        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    self.model_metadata = json.load(f)
            except (OSError, ValueError, RuntimeError) as e:
                logger.warning("Failed to load model metadata: %s", e)
                self.model_metadata = {}

    def _save_model_metadata(self):
        """Save model metadata to disk."""
        metadata_file = os.path.join(self.models_dir, 'model_metadata.json')

        try:
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(self.model_metadata, f, indent=2)
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to save model metadata: %s", e)

    def _detect_model_type(self, model_path: str) -> str:
        """Detect the model type from file extension or content."""
        file_ext = Path(model_path).suffix.lower().lstrip('.')

        # Direct extension mapping
        if file_ext in self.backends:
            return file_ext

        # Special cases
        if file_ext == 'json' and os.path.exists(model_path.replace('.json', '.bin')):
            return 'tensorflow'

        if os.path.isdir(model_path):
            # Check for TensorFlow SavedModel format
            if os.path.exists(os.path.join(model_path, 'saved_model.pb')):
                return 'savedmodel'

        # Default fallback
        return 'sklearn'

    def register_model(self, model_id: str, model_path: str,
                      model_type: str = None, metadata: Dict[str, Any] = None):
        """Register a model with the manager."""
        with self.lock:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")

            if model_type is None:
                model_type = self._detect_model_type(model_path)

            if model_type not in self.backends:
                raise ValueError(f"Unsupported model type: {model_type}")

            self.model_metadata[model_id] = {
                'path': model_path,
                'type': model_type,
                'registered': datetime.now().isoformat(),
                'metadata': metadata or {}
            }

            self._save_model_metadata()
            logger.info("Registered model: %s (%s)", model_id, model_type)

    def load_model(self, model_id: str) -> Any:
        """Load a model by ID."""
        with self.lock:
            if model_id not in self.model_metadata:
                raise ValueError(f"Model not registered: {model_id}")

            # Check if already loaded
            if model_id in self.loaded_models:
                return self.loaded_models[model_id]

            model_info = self.model_metadata[model_id]
            model_path = model_info['path']
            model_type = model_info['type']

            # Check cache first
            cached_model = self.cache.get(model_path)
            if cached_model is not None:
                self.loaded_models[model_id] = cached_model
                return cached_model

            # Load the model
            backend = self.backends[model_type]
            model = backend.load_model(model_path)

            # Cache and store
            self.cache.put(model_path, model)
            self.loaded_models[model_id] = model

            logger.info("Loaded model: %s", model_id)
            return model

    def predict(self, model_id: str, input_data: Any) -> Any:
        """Make predictions using a model."""
        model = self.load_model(model_id)
        model_info = self.model_metadata[model_id]
        model_type = model_info['type']

        backend = self.backends[model_type]
        return backend.predict(model, input_data)

    def get_model_info(self, model_id: str) -> Dict[str, Any]:
        """Get information about a model."""
        if model_id not in self.model_metadata:
            raise ValueError(f"Model not registered: {model_id}")

        model_info = self.model_metadata[model_id].copy()

        # Add runtime info if model is loaded
        if model_id in self.loaded_models:
            model = self.loaded_models[model_id]
            model_type = model_info['type']
            backend = self.backends[model_type]

            runtime_info = backend.get_model_info(model)
            model_info.update(runtime_info)
            model_info['loaded'] = True
        else:
            model_info['loaded'] = False

        return model_info

    def list_models(self) -> List[str]:
        """List all registered models."""
        return list(self.model_metadata.keys())

    def unload_model(self, model_id: str):
        """Unload a model from memory."""
        with self.lock:
            if model_id in self.loaded_models:
                del self.loaded_models[model_id]
                logger.info("Unloaded model: %s", model_id)

    def unregister_model(self, model_id: str):
        """Unregister a model."""
        with self.lock:
            if model_id in self.model_metadata:
                del self.model_metadata[model_id]
                self._save_model_metadata()

            if model_id in self.loaded_models:
                del self.loaded_models[model_id]

            logger.info("Unregistered model: %s", model_id)

    def get_available_backends(self) -> List[str]:
        """Get list of available backends."""
        return list(self.backends.keys())

    def clear_cache(self):
        """Clear the model cache."""
        self.cache.clear()

    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache information."""
        return self.cache.get_cache_info()

    def get_manager_stats(self) -> Dict[str, Any]:
        """Get manager statistics."""
        with self.lock:
            return {
                'registered_models': len(self.model_metadata),
                'loaded_models': len(self.loaded_models),
                'available_backends': self.get_available_backends(),
                'models_directory': self.models_dir,
                'cache_info': self.get_cache_info()
            }

    def import_local_model(self, file_path: str) -> Dict[str, Any]:
        """Import a local model file."""
        try:
            if not os.path.exists(file_path):
                return None

            model_name = os.path.basename(file_path)
            model_id = f"local_{model_name}"
            model_type = self._detect_model_type(file_path)

            self.register_model(model_id, file_path, model_type)

            return {
                'model_id': model_id,
                'local_path': file_path,
                'name': model_name,
                'type': model_type
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to import local model: %s", e)
            return None

    def get_available_repositories(self) -> List[str]:
        """Get list of available model repositories."""
        return ['huggingface', 'local', 'custom']

    def get_available_models(self, repository: str = None) -> List[Dict[str, Any]]:
        """Get list of available models."""
        models = []
        for model_id, metadata in self.model_metadata.items():
            model_info = {
                'id': model_id,
                'name': model_id,
                'type': metadata.get('type', 'unknown'),
                'path': metadata.get('path', ''),
                'repository': repository or 'local'
            }
            models.append(model_info)
        return models

    def get_model_path(self, model_id: str) -> str:
        """Get the file path for a model."""
        if model_id in self.model_metadata:
            model_info = self.model_metadata[model_id]
            path = model_info.get('path', '')

            # Handle different model types
            if model_info.get('type') == 'api':
                # API models return their API endpoint
                return path
            elif model_info.get('type') == 'repository':
                # Repository models may need path resolution
                repo_name = model_info.get('repository', '')
                model_name = model_info.get('model_name', model_id)
                if repo_name and model_name:
                    # Construct path to downloaded model
                    repo_dir = os.path.join(self.models_dir, 'repositories', repo_name)
                    model_path = os.path.join(repo_dir, model_name)
                    if os.path.exists(model_path):
                        return model_path
                    # Try with common extensions
                    for ext in ['.pth', '.h5', '.onnx', '.pkl', '.joblib']:
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
                os.path.join(self.models_dir, 'downloads', model_id),
                os.path.join(self.models_dir, 'downloads', f"{model_id}.pth"),
            ]

            for p in possible_paths:
                if os.path.exists(p):
                    # Update metadata with found path
                    self.model_metadata[model_id]['path'] = p
                    self._save_model_metadata()
                    return p

        # Model not found - return empty string
        logger.warning(f"Model path not found for model_id: {model_id}")
        return ''

    def import_api_model(self, model_name: str, api_config: Dict[str, Any]) -> Dict[str, Any]:
        """Import a model from an API."""
        try:
            model_id = f"api_{model_name}"

            # Store API configuration in metadata
            self.model_metadata[model_id] = {
                'path': f"api://{model_name}",
                'type': 'api',
                'registered': datetime.now().isoformat(),
                'metadata': api_config
            }

            self._save_model_metadata()

            return {
                'model_id': model_id,
                'name': model_name,
                'type': 'api',
                'config': api_config
            }
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to import API model: %s", e)
            return None

    @property
    def repositories(self) -> List[str]:
        """Get available repositories."""
        return self.get_available_repositories()


class AsyncModelManager:
    """Asynchronous wrapper for model operations."""

    def __init__(self, model_manager: ModelManager):
        self.model_manager = model_manager
        self.thread_pool = {}

    def load_model_async(self, model_id: str, callback: Callable = None):
        """Load a model asynchronously."""
        def load_worker():
            """
            Worker function to load a model asynchronously.
            
            Attempts to load the specified model and calls the callback with the result.
            On success, passes (True, model, None) to callback.
            On failure, passes (False, None, error_message) to callback.
            """
            try:
                model = self.model_manager.load_model(model_id)
                if callback:
                    callback(True, model, None)
            except (OSError, ValueError, RuntimeError) as e:
                if callback:
                    callback(False, None, str(e))

        thread = threading.Thread(target=load_worker, daemon=True)
        self.thread_pool[model_id] = thread
        thread.start()
        return thread

    def predict_async(self, model_id: str, input_data: Any, callback: Callable = None):
        """Make predictions asynchronously."""
        def predict_worker():
            """
            Worker function to make predictions asynchronously.
            
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
_global_model_manager = None

def get_global_model_manager() -> ModelManager:
    """Get the global model manager instance."""
    global _global_model_manager  # pylint: disable=global-statement
    if _global_model_manager is None:
        _global_model_manager = create_model_manager()
    return _global_model_manager


class ModelFineTuner:
    """Fine-tuning support for AI models."""

    def __init__(self, model_manager: ModelManager):
        self.model_manager = model_manager
        self.training_history = {}
        self.lock = threading.RLock()

    def fine_tune_model(self, model_id: str, training_data: Any,
                       validation_data: Any = None, epochs: int = 10,
                       learning_rate: float = 0.001, batch_size: int = 32,
                       callback: Callable = None) -> Dict[str, Any]:
        """
        Fine-tune a pre-trained model on custom data.

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
            model_type = model_info['type']

            results = {
                'model_id': model_id,
                'epochs': epochs,
                'training_loss': [],
                'validation_loss': [],
                'metrics': {},
                'fine_tuned_model_path': None
            }

            try:
                if model_type in ['pytorch', 'pth'] and HAS_TORCH:
                    results = self._fine_tune_pytorch(
                        model, training_data, validation_data,
                        epochs, learning_rate, batch_size, callback
                    )
                elif model_type in ['tensorflow', 'h5'] and HAS_TENSORFLOW:
                    results = self._fine_tune_tensorflow(
                        model, training_data, validation_data,
                        epochs, learning_rate, batch_size, callback
                    )
                elif model_type in ['sklearn', 'joblib'] and HAS_JOBLIB:
                    results = self._fine_tune_sklearn(
                        model, training_data, validation_data, callback
                    )
                else:
                    raise ValueError(f"Fine-tuning not supported for model type: {model_type}")

                # Save fine-tuned model
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                fine_tuned_id = f"{model_id}_finetuned_{timestamp}"
                fine_tuned_path = os.path.join(
                    self.model_manager.models_dir,
                    f"{fine_tuned_id}.{model_type}"
                )

                # Save the model
                backend = self.model_manager.backends[model_type]
                if hasattr(backend, 'save_model'):
                    backend.save_model(model, fine_tuned_path)
                else:
                    # Default save methods
                    if model_type in ['pytorch', 'pth']:
                        torch.save(model, fine_tuned_path)
                    elif model_type in ['tensorflow', 'h5']:
                        model.save(fine_tuned_path)
                    elif model_type in ['sklearn', 'joblib']:
                        joblib.dump(model, fine_tuned_path)

                # Register the fine-tuned model
                self.model_manager.register_model(
                    fine_tuned_id, fine_tuned_path, model_type,
                    metadata={
                        'base_model': model_id,
                        'fine_tuning_params': {
                            'epochs': epochs,
                            'learning_rate': learning_rate,
                            'batch_size': batch_size
                        },
                        'results': results
                    }
                )

                results['fine_tuned_model_id'] = fine_tuned_id
                results['fine_tuned_model_path'] = fine_tuned_path

                # Store training history
                self.training_history[fine_tuned_id] = results

                logger.info("Fine-tuning completed. New model ID: %s", fine_tuned_id)

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Fine-tuning failed: %s", e)
                results['error'] = str(e)

            return results

    def _fine_tune_pytorch(self, model: Any, training_data: Any,
                          validation_data: Any, epochs: int,
                          learning_rate: float, batch_size: int,
                          callback: Callable) -> Dict[str, Any]:
        """Fine-tune a PyTorch model."""
        if not HAS_TORCH or torch is None or nn is None:
            return {"error": "PyTorch not available"}

        try:
            import torch.optim as optim  # pylint: disable=import-error
            from torch.utils.data import DataLoader, TensorDataset
        except ImportError:
            return {"error": "PyTorch components not available"}

        # Set model to training mode
        model.train()

        # Create optimizer
        optimizer = optim.Adam(model.parameters(), lr=learning_rate)
        criterion = nn.CrossEntropyLoss()

        # Prepare data loaders
        train_dataset = TensorDataset(
            torch.tensor(training_data[0]).float(),
            torch.tensor(training_data[1]).long()
        )
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

        val_loader = None
        if validation_data is not None:
            val_dataset = TensorDataset(
                torch.tensor(validation_data[0]).float(),
                torch.tensor(validation_data[1]).long()
            )
            val_loader = DataLoader(val_dataset, batch_size=batch_size)

        results = {
            'training_loss': [],
            'validation_loss': []
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
            results['training_loss'].append(avg_train_loss)

            # Validation phase
            if val_loader:
                model.eval()
                val_loss = 0.0
                with torch.no_grad():
                    for data, target in val_loader:
                        output = model(data)
                        val_loss += criterion(output, target).item()

                avg_val_loss = val_loss / len(val_loader)
                results['validation_loss'].append(avg_val_loss)
                model.train()

            # Callback for progress updates
            if callback:
                callback(_epoch + 1, epochs, avg_train_loss,
                        avg_val_loss if val_loader else None)

        return results

    def _fine_tune_tensorflow(self, model: Any, training_data: Any,
                             validation_data: Any, epochs: int,
                             learning_rate: float, batch_size: int,
                             callback: Callable) -> Dict[str, Any]:
        """Fine-tune a TensorFlow model."""
        # Compile model with new learning rate
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),  # pylint: disable=no-member
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )

        # Prepare callbacks
        callbacks = []
        if callback:
            class ProgressCallback(tf.keras.callbacks.Callback):  # pylint: disable=no-member
                """
                Keras callback to report training progress to the parent callback.
                
                Inherits from tf.keras.callbacks.Callback to intercept training events
                and forward progress information to the user-provided callback function.
                """
                def on_epoch_end(self, epoch, logs=None):
                    """
                    Called at the end of each training epoch.
                    
                    Args:
                        epoch: Current epoch number (0-indexed)
                        logs: Dictionary containing training metrics (loss, val_loss, etc.)
                    """
                    callback(epoch + 1, epochs, logs.get('loss'),
                            logs.get('val_loss'))
            callbacks.append(ProgressCallback())

        # Train the model
        history = model.fit(
            training_data[0], training_data[1],
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=0
        )

        return {
            'training_loss': history.history['loss'],
            'validation_loss': history.history.get('val_loss', []),
            'metrics': history.history
        }

    def _fine_tune_sklearn(self, model: Any, training_data: Any,
                          validation_data: Any, callback: Callable) -> Dict[str, Any]:
        """Fine-tune a scikit-learn model."""
        # For sklearn, we typically retrain on new data
        X_train, y_train = training_data

        # Partial fit if supported, otherwise full refit
        if hasattr(model, 'partial_fit'):
            model.partial_fit(X_train, y_train)
        else:
            model.fit(X_train, y_train)

        results = {'training_complete': True}

        # Calculate validation score if data provided
        if validation_data is not None:
            X_val, y_val = validation_data
            val_score = model.score(X_val, y_val)
            results['validation_score'] = val_score

        if callback:
            callback(1, 1, None, results.get('validation_score'))

        return results

    def get_training_history(self, model_id: str) -> Optional[Dict[str, Any]]:
        """Get training history for a fine-tuned model."""
        return self.training_history.get(model_id)


def import_custom_model(model_path: str, model_type: str = None,
                       model_id: str = None) -> Dict[str, Any]:
    """
    Import a custom AI model into the system.

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
            'success': True,
            'model_id': model_id,
            'model_path': model_path,
            'model_info': model_info
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to import model: %s", e)
        return {
            'success': False,
            'error': str(e),
            'model_id': model_id,
            'model_path': model_path
        }


# Standalone convenience functions for backward compatibility

def load_model(model_id: str, model_path: Optional[str] = None):
    """
    Load a model using the global model manager.
    
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
                '.pkl': 'sklearn',
                '.joblib': 'sklearn',
                '.pt': 'pytorch',
                '.pth': 'pytorch',
                '.onnx': 'onnx',
                '.pb': 'tensorflow',
                '.h5': 'tensorflow'
            }
            model_type = model_type_map.get(ext, 'sklearn')

            manager.register_model(model_id, model_path, model_type)

        return manager.load_model(model_id)

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to load model %s: %s", model_id, e)
        raise


def save_model(model_id: str, save_path: str, model_format: str = "auto"):
    """
    Save a loaded model to disk.
    
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
                '.pkl': 'pickle',
                '.joblib': 'joblib',
                '.pt': 'pytorch',
                '.pth': 'pytorch',
                '.onnx': 'onnx',
                '.h5': 'tensorflow'
            }
            model_format = format_map.get(ext, 'pickle')

        # Save based on format
        if model_format in ['pickle', 'pkl']:
            import pickle as pickle_lib
            with open(save_path, 'wb') as f:
                pickle_lib.dump(model, f)
        elif model_format == 'joblib':
            if HAS_JOBLIB:
                joblib.dump(model, save_path)
            else:
                import pickle as pickle_lib
                with open(save_path, 'wb') as f:
                    pickle_lib.dump(model, f)
        elif model_format == 'pytorch':
            if HAS_TORCH and torch is not None:
                torch.save(model, save_path)
            else:
                raise ImportError("PyTorch not available for saving .pt/.pth files")
        else:
            # Default to pickle
            import pickle as pickle_lib
            with open(save_path, 'wb') as f:
                pickle_lib.dump(model, f)

        return {
            "success": True,
            "model_id": model_id,
            "save_path": save_path,
            "format": model_format
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to save model %s: %s", model_id, e)
        return {
            "success": False,
            "error": str(e),
            "model_id": model_id,
            "save_path": save_path
        }


def list_available_models() -> Dict[str, Any]:
    """
    List all available models in the global manager.
    
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
                detailed_models[_model_id] = {"error": str(e)}

        return {
            "success": True,
            "model_count": len(models),
            "models": detailed_models
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to list models: %s", e)
        return {
            "success": False,
            "error": str(e),
            "models": {}
        }


def configure_ai_provider(provider_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Configure an AI provider for the model manager.
    
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
            "sklearn": "Scikit-learn models"
        }

        if provider_name not in supported_providers:
            return {
                "success": False,
                "error": f"Unsupported provider: {provider_name}",
                "supported_providers": list(supported_providers.keys())
            }

        # Store configuration (in a real implementation, this would be persistent)
        logger.info("Configured AI provider: %s", provider_name)

        return {
            "success": True,
            "provider": provider_name,
            "description": supported_providers[provider_name],
            "config": config,
            "message": f"Provider {provider_name} configured successfully"
        }

    except (OSError, ValueError, RuntimeError) as e:
        logger.error("Failed to configure AI provider %s: %s", provider_name, e)
        return {
            "success": False,
            "error": str(e),
            "provider": provider_name
        }


# Export for external use
__all__ = [
    'ModelManager', 'AsyncModelManager', 'ModelCache',
    'PyTorchBackend', 'TensorFlowBackend', 'ONNXBackend', 'SklearnBackend', 'ModelBackend',
    'create_model_manager', 'get_global_model_manager',
    'ModelFineTuner', 'import_custom_model',
    'load_model', 'save_model', 'list_available_models', 'configure_ai_provider'
]
