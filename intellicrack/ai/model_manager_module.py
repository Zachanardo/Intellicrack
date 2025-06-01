"""AI Model Manager Module for Intellicrack.

This module provides comprehensive AI model management capabilities including
model loading, caching, inference, and integration with various AI backends.
"""

import os
import sys
import json
import time
import hashlib
import pickle
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from pathlib import Path
import logging
from abc import ABC, abstractmethod

# Optional imports with graceful fallbacks
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import torch
    import torch.nn as nn
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

try:
    import tensorflow as tf
    HAS_TENSORFLOW = True
except ImportError:
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
        if not HAS_TORCH:
            raise ImportError("PyTorch not available")
        
        try:
            model = torch.load(model_path, map_location='cpu')
            if hasattr(model, 'eval'):
                model.eval()
            return model
        except Exception as e:
            logger.error(f"Failed to load PyTorch model: {e}")
            raise
    
    def predict(self, model: Any, input_data: Any) -> Any:
        """Make predictions using PyTorch model."""
        if not HAS_TORCH:
            raise ImportError("PyTorch not available")
        
        try:
            if isinstance(input_data, np.ndarray):
                input_tensor = torch.from_numpy(input_data).float()
            elif not isinstance(input_data, torch.Tensor):
                input_tensor = torch.tensor(input_data).float()
            else:
                input_tensor = input_data
            
            with torch.no_grad():
                output = model(input_tensor)
            
            return output.numpy() if hasattr(output, 'numpy') else output
        except Exception as e:
            logger.error(f"PyTorch prediction failed: {e}")
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
                info['parameters'] = sum(p.numel() for p in model.parameters())
            except:
                pass
        
        return info


class TensorFlowBackend(ModelBackend):
    """TensorFlow model backend."""
    
    def load_model(self, model_path: str) -> Any:
        """Load a TensorFlow model."""
        if not HAS_TENSORFLOW:
            raise ImportError("TensorFlow not available")
        
        try:
            model = tf.keras.models.load_model(model_path)
            return model
        except Exception as e:
            logger.error(f"Failed to load TensorFlow model: {e}")
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
        except Exception as e:
            logger.error(f"TensorFlow prediction failed: {e}")
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
            except:
                pass
        
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
        except Exception as e:
            logger.error(f"Failed to load ONNX model: {e}")
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
        except Exception as e:
            logger.error(f"ONNX prediction failed: {e}")
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
            for input_meta in model.get_inputs():
                info['inputs'].append({
                    'name': input_meta.name,
                    'shape': input_meta.shape,
                    'type': input_meta.type
                })
            
            for output_meta in model.get_outputs():
                info['outputs'].append({
                    'name': output_meta.name,
                    'shape': output_meta.shape,
                    'type': output_meta.type
                })
        except:
            pass
        
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
        except Exception as e:
            logger.error(f"Failed to load sklearn model: {e}")
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
        except Exception as e:
            logger.error(f"Sklearn prediction failed: {e}")
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
            return hashlib.md5(key_string.encode()).hexdigest()
        except:
            return hashlib.md5(model_path.encode()).hexdigest()
    
    def get(self, model_path: str) -> Optional[Any]:
        """Get model from cache."""
        with self.lock:
            cache_key = self._get_cache_key(model_path)
            
            if cache_key in self.cache:
                self.access_times[cache_key] = time.time()
                logger.debug(f"Model cache hit for {model_path}")
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
            logger.debug(f"Model cached for {model_path}")
    
    def _evict_oldest(self):
        """Evict the oldest accessed model from cache."""
        if not self.access_times:
            return
        
        oldest_key = min(self.access_times, key=self.access_times.get)
        del self.cache[oldest_key]
        del self.access_times[oldest_key]
        logger.debug(f"Evicted model from cache: {oldest_key}")
    
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
                with open(metadata_file, 'r') as f:
                    self.model_metadata = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load model metadata: {e}")
                self.model_metadata = {}
    
    def _save_model_metadata(self):
        """Save model metadata to disk."""
        metadata_file = os.path.join(self.models_dir, 'model_metadata.json')
        
        try:
            with open(metadata_file, 'w') as f:
                json.dump(self.model_metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save model metadata: {e}")
    
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
            logger.info(f"Registered model: {model_id} ({model_type})")
    
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
            
            logger.info(f"Loaded model: {model_id}")
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
                logger.info(f"Unloaded model: {model_id}")
    
    def unregister_model(self, model_id: str):
        """Unregister a model."""
        with self.lock:
            if model_id in self.model_metadata:
                del self.model_metadata[model_id]
                self._save_model_metadata()
            
            if model_id in self.loaded_models:
                del self.loaded_models[model_id]
            
            logger.info(f"Unregistered model: {model_id}")
    
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


class AsyncModelManager:
    """Asynchronous wrapper for model operations."""
    
    def __init__(self, model_manager: ModelManager):
        self.model_manager = model_manager
        self.thread_pool = {}
        
    def load_model_async(self, model_id: str, callback: Callable = None):
        """Load a model asynchronously."""
        def load_worker():
            try:
                model = self.model_manager.load_model(model_id)
                if callback:
                    callback(True, model, None)
            except Exception as e:
                if callback:
                    callback(False, None, str(e))
        
        thread = threading.Thread(target=load_worker, daemon=True)
        self.thread_pool[model_id] = thread
        thread.start()
        return thread
    
    def predict_async(self, model_id: str, input_data: Any, callback: Callable = None):
        """Make predictions asynchronously."""
        def predict_worker():
            try:
                result = self.model_manager.predict(model_id, input_data)
                if callback:
                    callback(True, result, None)
            except Exception as e:
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
    global _global_model_manager
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
                
                logger.info(f"Fine-tuning completed. New model ID: {fine_tuned_id}")
                
            except Exception as e:
                logger.error(f"Fine-tuning failed: {e}")
                results['error'] = str(e)
            
            return results
    
    def _fine_tune_pytorch(self, model: Any, training_data: Any,
                          validation_data: Any, epochs: int,
                          learning_rate: float, batch_size: int,
                          callback: Callable) -> Dict[str, Any]:
        """Fine-tune a PyTorch model."""
        import torch.optim as optim
        from torch.utils.data import DataLoader, TensorDataset
        
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
        for epoch in range(epochs):
            # Training phase
            train_loss = 0.0
            for batch_idx, (data, target) in enumerate(train_loader):
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
                callback(epoch + 1, epochs, avg_train_loss, 
                        avg_val_loss if val_loader else None)
        
        return results
    
    def _fine_tune_tensorflow(self, model: Any, training_data: Any,
                             validation_data: Any, epochs: int,
                             learning_rate: float, batch_size: int,
                             callback: Callable) -> Dict[str, Any]:
        """Fine-tune a TensorFlow model."""
        # Compile model with new learning rate
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        # Prepare callbacks
        callbacks = []
        if callback:
            class ProgressCallback(tf.keras.callbacks.Callback):
                def on_epoch_end(self, epoch, logs=None):
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
        model = manager.load_model(model_id)
        
        # Get model information
        model_info = manager.get_model_info(model_id)
        
        return {
            'success': True,
            'model_id': model_id,
            'model_path': model_path,
            'model_info': model_info
        }
        
    except Exception as e:
        logger.error(f"Failed to import model: {e}")
        return {
            'success': False,
            'error': str(e),
            'model_id': model_id,
            'model_path': model_path
        }


# Export for external use
__all__ = [
    'ModelManager', 'AsyncModelManager', 'ModelCache',
    'PyTorchBackend', 'TensorFlowBackend', 'ONNXBackend', 'SklearnBackend',
    'create_model_manager', 'get_global_model_manager',
    'ModelFineTuner', 'import_custom_model'
]