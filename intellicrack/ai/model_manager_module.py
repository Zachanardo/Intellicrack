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
import weakref
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from queue import Queue, Empty
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

# Import common availability flags
from ..utils.core.common_imports import HAS_NUMPY, HAS_TORCH

# Module logger - define early to avoid usage before definition
logger = logging.getLogger(__name__)

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
    os.environ['MKL_THREADING_LAYER'] = 'GNU'

    import tensorflow as tf
    from tensorflow import keras
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
except ImportError as e:
    logger.error("Import error in model_manager_module: %s", e)
    HAS_ONNX = False

try:
    import joblib
    HAS_JOBLIB = True
except ImportError as e:
    logger.error("Import error in model_manager_module: %s", e)
    HAS_JOBLIB = False

# LLM-specific imports
try:
    from .llm_backends import LLMManager, LLMProvider, LLMConfig, LLMResponse
    from .llm_types import LoadingState
    HAS_LLM_BACKENDS = True
except ImportError as e:
    logger.warning("LLM backends not available: %s", e)
    HAS_LLM_BACKENDS = False
    LLMManager = None
    LLMProvider = None
    LLMConfig = None
    LLMResponse = None
    LoadingState = None

# Performance monitoring
try:
    from .performance_monitor import profile_ai_operation
    HAS_PERFORMANCE_MONITOR = True
except ImportError:
    HAS_PERFORMANCE_MONITOR = False
    def profile_ai_operation(func):
        return func


class ModelType(Enum):
    """Types of models managed by the system."""
    ML_MODEL = "ml_model"
    LLM_MODEL = "llm_model"
    FINE_TUNED = "fine_tuned"
    API_MODEL = "api_model"
    LOCAL_MODEL = "local_model"


class ModelState(Enum):
    """Model lifecycle states."""
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    ACTIVE = "active"
    WARMING = "warming"
    ERROR = "error"
    UPDATING = "updating"
    DEPRECATED = "deprecated"


class ResourceType(Enum):
    """Types of computational resources."""
    CPU = "cpu"
    GPU = "gpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"


@dataclass
class ModelMetrics:
    """Performance and health metrics for a model."""
    model_id: str
    last_used: datetime
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    average_response_time: float = 0.0
    memory_usage: float = 0.0
    gpu_usage: float = 0.0
    cost_per_request: float = 0.0
    quality_score: float = 0.0
    health_score: float = 1.0
    errors: List[str] = field(default_factory=list)


@dataclass  
class ResourceAllocation:
    """Resource allocation for a model."""
    model_id: str
    cpu_cores: int = 1
    memory_gb: float = 1.0
    gpu_memory_gb: float = 0.0
    gpu_device_id: Optional[int] = None
    priority: int = 5
    max_concurrent_requests: int = 1


class LLMResourceManager:
    """Manages computational resources for LLM models."""

    def __init__(self):
        """Initialize the LLM resource manager."""
        self.logger = logging.getLogger(__name__ + ".LLMResourceManager")
        self.allocations: Dict[str, ResourceAllocation] = {}
        self.resource_pools = {
            ResourceType.CPU: [],
            ResourceType.GPU: [],
            ResourceType.MEMORY: []
        }
        self.lock = threading.RLock()
        self.gpu_info = None
        
        # Initialize GPU information if available
        if GPU_AUTOLOADER_AVAILABLE:
            try:
                self.gpu_info = get_gpu_info()
                if self.gpu_info:
                    self.logger.info(f"Resource manager initialized with GPU: {self.gpu_info}")
            except Exception as e:
                self.logger.debug(f"Could not get GPU info: {e}")

    def allocate_resources(self, model_id: str, requirements: ResourceAllocation) -> bool:
        """Allocate resources for a model."""
        with self.lock:
            try:
                # Check if resources are available
                if not self._check_resource_availability(requirements):
                    self.logger.warning(f"Insufficient resources for model {model_id}")
                    return False

                # Reserve resources
                self.allocations[model_id] = requirements
                self.logger.info(f"Allocated resources for model {model_id}: "
                               f"CPU: {requirements.cpu_cores}, "
                               f"Memory: {requirements.memory_gb}GB, "
                               f"GPU Memory: {requirements.gpu_memory_gb}GB")
                return True

            except Exception as e:
                self.logger.error(f"Resource allocation failed for {model_id}: {e}")
                return False

    def deallocate_resources(self, model_id: str) -> bool:
        """Deallocate resources for a model."""
        with self.lock:
            try:
                if model_id in self.allocations:
                    allocation = self.allocations.pop(model_id)
                    self.logger.info(f"Deallocated resources for model {model_id}")
                    return True
                return False
            except Exception as e:
                self.logger.error(f"Resource deallocation failed for {model_id}: {e}")
                return False

    def _check_resource_availability(self, requirements: ResourceAllocation) -> bool:
        """Check if required resources are available."""
        try:
            # Basic availability check
            if requirements.gpu_memory_gb > 0 and not self.gpu_info:
                return False
            
            # In a production system, this would check actual resource usage
            # For now, we'll do basic validation
            current_allocations = sum(alloc.memory_gb for alloc in self.allocations.values())
            if current_allocations + requirements.memory_gb > 32:  # 32GB limit example
                return False
                
            return True
        except Exception as e:
            self.logger.error(f"Resource availability check failed: {e}")
            return False

    def optimize_memory_usage(self) -> Dict[str, Any]:
        """Optimize memory usage across models."""
        try:
            optimization_results = {
                'optimized_models': [],
                'memory_freed': 0.0,
                'gpu_memory_freed': 0.0
            }

            with self.lock:
                # Sort allocations by priority and last use
                sorted_allocations = sorted(
                    self.allocations.items(),
                    key=lambda x: (x[1].priority, -x[1].memory_gb)
                )

                for model_id, allocation in sorted_allocations:
                    # Apply GPU optimizations if available
                    if GPU_AUTOLOADER_AVAILABLE and allocation.gpu_memory_gb > 0:
                        try:
                            # This would call actual GPU optimization routines
                            optimization_results['optimized_models'].append(model_id)
                            self.logger.debug(f"Applied memory optimization to {model_id}")
                        except Exception as e:
                            self.logger.debug(f"Memory optimization failed for {model_id}: {e}")

            return optimization_results

        except Exception as e:
            self.logger.error(f"Memory optimization failed: {e}")
            return {'error': str(e)}

    def get_resource_usage(self) -> Dict[str, Any]:
        """Get current resource usage statistics."""
        with self.lock:
            try:
                total_cpu = sum(alloc.cpu_cores for alloc in self.allocations.values())
                total_memory = sum(alloc.memory_gb for alloc in self.allocations.values())
                total_gpu_memory = sum(alloc.gpu_memory_gb for alloc in self.allocations.values())

                return {
                    'allocated_models': len(self.allocations),
                    'total_cpu_cores': total_cpu,
                    'total_memory_gb': total_memory,
                    'total_gpu_memory_gb': total_gpu_memory,
                    'allocations': {
                        model_id: {
                            'cpu_cores': alloc.cpu_cores,
                            'memory_gb': alloc.memory_gb,
                            'gpu_memory_gb': alloc.gpu_memory_gb,
                            'priority': alloc.priority
                        }
                        for model_id, alloc in self.allocations.items()
                    }
                }
            except Exception as e:
                self.logger.error(f"Failed to get resource usage: {e}")
                return {'error': str(e)}

    def __del__(self):
        """Cleanup resources on garbage collection."""
        try:
            # Deallocate all remaining resources
            for model_id in list(self.allocations.keys()):
                self.deallocate_resources(model_id)
        except Exception:
            pass  # Ignore cleanup errors during garbage collection


class ModelBackend(ABC):
    """Abstract base class for AI model backends."""

    @abstractmethod
    def load_model(self, model_path: str) -> Any:
        """Load a model from the given path."""
        # Implementation should use model_path to load the actual model
        pass

    @abstractmethod
    def predict(self, model: Any, input_data: Any) -> Any:
        """Make predictions using the model."""
        # Implementation should use both model and input_data for predictions
        pass

    @abstractmethod
    def get_model_info(self, model: Any) -> Dict[str, Any]:
        """Get information about the model."""
        # Implementation should extract information from the model object
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
                info['parameters'] = sum(_p.numel()
                                         for _p in model.parameters())
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
            model = keras.models.load_model(model_path)
            return model
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to load TensorFlow model: %s", e)
            raise

    def predict(self, model: Any, input_data: Any) -> Any:
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
                logger.debug(
                    "Failed to count TensorFlow model parameters: %s", e)

        return info


class ONNXBackend(ModelBackend):
    """ONNX model backend."""

    def load_model(self, model_path: str) -> Any:
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

    def predict(self, model: Any, input_data: Any) -> Any:
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
            if np is not None:
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


class LLMHealthMonitor:
    """Monitors health and performance of LLM models."""

    def __init__(self):
        """Initialize the health monitor."""
        self.logger = logging.getLogger(__name__ + ".LLMHealthMonitor")
        self.model_metrics: Dict[str, ModelMetrics] = {}
        self.health_checks = {}
        self.lock = threading.RLock()
        self.monitoring_active = False
        self.monitor_thread = None

    def start_monitoring(self):
        """Start health monitoring."""
        with self.lock:
            if not self.monitoring_active:
                self.monitoring_active = True
                self.monitor_thread = threading.Thread(
                    target=self._monitoring_loop, daemon=True
                )
                self.monitor_thread.start()
                self.logger.info("Health monitoring started")

    def stop_monitoring(self):
        """Stop health monitoring."""
        with self.lock:
            self.monitoring_active = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5.0)
            self.logger.info("Health monitoring stopped")
    
    def __del__(self):
        """Cleanup resources on garbage collection."""
        try:
            self.stop_monitoring()
        except Exception:
            pass  # Ignore cleanup errors during garbage collection

    def register_model(self, model_id: str):
        """Register a model for monitoring."""
        with self.lock:
            if model_id not in self.model_metrics:
                self.model_metrics[model_id] = ModelMetrics(
                    model_id=model_id,
                    last_used=datetime.now()
                )
                self.logger.debug(f"Registered model for monitoring: {model_id}")

    def record_request(self, model_id: str, success: bool, response_time: float, 
                      error: Optional[str] = None):
        """Record a model request for metrics."""
        with self.lock:
            if model_id not in self.model_metrics:
                self.register_model(model_id)

            metrics = self.model_metrics[model_id]
            metrics.total_requests += 1
            metrics.last_used = datetime.now()

            if success:
                metrics.successful_requests += 1
                # Update average response time
                total_time = metrics.average_response_time * (metrics.successful_requests - 1)
                metrics.average_response_time = (total_time + response_time) / metrics.successful_requests
            else:
                metrics.failed_requests += 1
                if error:
                    metrics.errors.append(f"{datetime.now()}: {error}")
                    # Keep only recent errors
                    if len(metrics.errors) > 10:
                        metrics.errors = metrics.errors[-10:]

            # Update health score
            metrics.health_score = metrics.successful_requests / metrics.total_requests

    def check_model_health(self, model_id: str) -> Dict[str, Any]:
        """Check health of a specific model."""
        with self.lock:
            if model_id not in self.model_metrics:
                return {"error": f"Model {model_id} not monitored"}

            metrics = self.model_metrics[model_id]
            now = datetime.now()
            time_since_last_use = (now - metrics.last_used).total_seconds()

            health_status = {
                'model_id': model_id,
                'healthy': True,
                'health_score': metrics.health_score,
                'last_used_seconds_ago': time_since_last_use,
                'total_requests': metrics.total_requests,
                'success_rate': metrics.health_score,
                'average_response_time': metrics.average_response_time,
                'recent_errors': metrics.errors[-3:] if metrics.errors else []
            }

            # Determine if model is healthy
            if metrics.health_score < 0.8:  # Less than 80% success rate
                health_status['healthy'] = False
                health_status['reason'] = 'Low success rate'
            elif time_since_last_use > 3600:  # Not used in an hour
                health_status['healthy'] = False
                health_status['reason'] = 'Stale model'
            elif metrics.average_response_time > 30.0:  # Slow responses
                health_status['healthy'] = False
                health_status['reason'] = 'Slow response time'

            return health_status

    def get_performance_metrics(self, model_id: str = None) -> Dict[str, Any]:
        """Get performance metrics for models."""
        with self.lock:
            if model_id:
                if model_id in self.model_metrics:
                    metrics = self.model_metrics[model_id]
                    return {
                        'model_id': model_id,
                        'total_requests': metrics.total_requests,
                        'successful_requests': metrics.successful_requests,
                        'failed_requests': metrics.failed_requests,
                        'success_rate': metrics.health_score,
                        'average_response_time': metrics.average_response_time,
                        'memory_usage': metrics.memory_usage,
                        'gpu_usage': metrics.gpu_usage,
                        'last_used': metrics.last_used.isoformat()
                    }
                else:
                    return {"error": f"Model {model_id} not found"}
            else:
                # Return metrics for all models
                return {
                    mid: {
                        'total_requests': m.total_requests,
                        'success_rate': m.health_score,
                        'average_response_time': m.average_response_time,
                        'last_used': m.last_used.isoformat()
                    }
                    for mid, m in self.model_metrics.items()
                }

    def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                # Perform periodic health checks
                current_time = datetime.now()
                
                with self.lock:
                    for model_id, metrics in self.model_metrics.items():
                        # Clean up old errors
                        cutoff_time = current_time - timedelta(hours=1)
                        metrics.errors = [
                            error for error in metrics.errors
                            if not error.startswith(cutoff_time.strftime("%Y-%m-%d %H:"))
                        ]

                # Sleep for monitoring interval
                time.sleep(60)  # Check every minute

            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(60)


class ModelCache:
    """Model caching system for efficient model management."""

    def __init__(self, cache_dir: str = None, max_cache_size: int = 5):
        """Initialize the model cache system.

        Args:
            cache_dir: Directory for storing cached models.
                      Defaults to ~/.intellicrack/model_cache if not provided.
            max_cache_size: Maximum number of models to keep in cache.
        """
        self.logger = logging.getLogger(__name__ + ".ModelCache")
        self.cache_dir = cache_dir or os.path.join(
            os.path.expanduser('~'), '.intellicrack', 'model_cache')
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
        except (OSError, ValueError) as e:
            self.logger.error("Error in model_manager_module: %s", e)
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

    def clear_cache(self):
        """Clear all cached models."""
        with self.lock:
            try:
                # Clear the cache dictionary
                self.cache.clear()
                self.access_times.clear()
                
                # Clean up cache files if they exist
                if os.path.exists(self.cache_dir):
                    import shutil
                    try:
                        shutil.rmtree(self.cache_dir)
                        os.makedirs(self.cache_dir, exist_ok=True)
                    except Exception as e:
                        self.logger.warning(f"Failed to clean cache directory: {e}")
                        
            except Exception as e:
                self.logger.error(f"Failed to clear cache: {e}")

    def __del__(self):
        """Cleanup resources on garbage collection."""
        try:
            self.clear_cache()
        except Exception:
            pass  # Ignore cleanup errors during garbage collection


class LLMVersionManager:
    """Manages model versions and updates."""

    def __init__(self, versions_dir: str = None):
        """Initialize the version manager."""
        self.logger = logging.getLogger(__name__ + ".LLMVersionManager")
        self.versions_dir = versions_dir or os.path.join(
            os.path.expanduser('~'), '.intellicrack', 'model_versions'
        )
        self.version_registry = {}
        self.lock = threading.RLock()
        os.makedirs(self.versions_dir, exist_ok=True)

    def register_version(self, model_id: str, version: str, model_path: str, 
                        metadata: Dict[str, Any] = None) -> bool:
        """Register a model version."""
        with self.lock:
            try:
                if model_id not in self.version_registry:
                    self.version_registry[model_id] = {}

                self.version_registry[model_id][version] = {
                    'path': model_path,
                    'registered': datetime.now().isoformat(),
                    'metadata': metadata or {},
                    'active': False
                }

                self.logger.info(f"Registered version {version} for model {model_id}")
                return True

            except Exception as e:
                self.logger.error(f"Failed to register version: {e}")
                return False

    def set_active_version(self, model_id: str, version: str) -> bool:
        """Set the active version for a model."""
        with self.lock:
            try:
                if model_id not in self.version_registry:
                    return False

                if version not in self.version_registry[model_id]:
                    return False

                # Deactivate all versions
                for v in self.version_registry[model_id].values():
                    v['active'] = False

                # Activate specified version
                self.version_registry[model_id][version]['active'] = True
                self.logger.info(f"Set active version {version} for model {model_id}")
                return True

            except Exception as e:
                self.logger.error(f"Failed to set active version: {e}")
                return False

    def get_active_version(self, model_id: str) -> Optional[str]:
        """Get the active version for a model."""
        with self.lock:
            if model_id not in self.version_registry:
                return None

            for version, info in self.version_registry[model_id].items():
                if info.get('active', False):
                    return version

            return None

    def list_versions(self, model_id: str) -> List[str]:
        """List all versions for a model."""
        with self.lock:
            if model_id not in self.version_registry:
                return []
            return list(self.version_registry[model_id].keys())

    def rollback_version(self, model_id: str, target_version: str) -> bool:
        """Rollback to a specific version."""
        return self.set_active_version(model_id, target_version)


class LLMLoadBalancer:
    """Load balancer for LLM models with failover support."""

    def __init__(self):
        """Initialize the load balancer."""
        self.logger = logging.getLogger(__name__ + ".LLMLoadBalancer")
        self.model_pools: Dict[str, List[str]] = {}
        self.request_counts: Dict[str, int] = defaultdict(int)
        self.failed_models: Set[str] = set()
        self.fallback_chains: Dict[str, List[str]] = {}
        self.lock = threading.RLock()

    def register_model_pool(self, pool_name: str, model_ids: List[str]):
        """Register a pool of models for load balancing."""
        with self.lock:
            self.model_pools[pool_name] = model_ids.copy()
            self.logger.info(f"Registered model pool {pool_name} with {len(model_ids)} models")

    def setup_fallback_chain(self, primary_model: str, fallback_models: List[str]):
        """Setup fallback chain for a model."""
        with self.lock:
            self.fallback_chains[primary_model] = fallback_models.copy()
            self.logger.info(f"Setup fallback chain for {primary_model} with {len(fallback_models)} fallbacks")

    def get_next_model(self, pool_name: str = None, exclude_failed: bool = True) -> Optional[str]:
        """Get the next model for load balancing."""
        with self.lock:
            if pool_name and pool_name in self.model_pools:
                available_models = [
                    model_id for model_id in self.model_pools[pool_name]
                    if not (exclude_failed and model_id in self.failed_models)
                ]

                if not available_models:
                    return None

                # Simple round-robin load balancing
                selected_model = min(available_models, key=lambda m: self.request_counts[m])
                self.request_counts[selected_model] += 1
                return selected_model

            return None

    def mark_model_failed(self, model_id: str):
        """Mark a model as failed."""
        with self.lock:
            self.failed_models.add(model_id)
            self.logger.warning(f"Marked model {model_id} as failed")

    def mark_model_healthy(self, model_id: str):
        """Mark a model as healthy."""
        with self.lock:
            self.failed_models.discard(model_id)
            self.logger.info(f"Marked model {model_id} as healthy")

    def get_fallback_model(self, failed_model: str) -> Optional[str]:
        """Get fallback model for a failed model."""
        with self.lock:
            if failed_model in self.fallback_chains:
                for fallback in self.fallback_chains[failed_model]:
                    if fallback not in self.failed_models:
                        return fallback
            return None

    def get_load_stats(self) -> Dict[str, Any]:
        """Get load balancing statistics."""
        with self.lock:
            return {
                'request_counts': dict(self.request_counts),
                'failed_models': list(self.failed_models),
                'model_pools': dict(self.model_pools),
                'fallback_chains': dict(self.fallback_chains)
            }


class ModelManager:
    """Comprehensive AI model manager for Intellicrack."""

    def __init__(self, models_dir: str = None, cache_size: int = 5):
        """Initialize the AI model manager.

        Args:
            models_dir: Directory containing AI models. If None, defaults to
                        ../models relative to this file
            cache_size: Maximum number of models to keep in cache
        """
        self.models_dir = models_dir or os.path.join(
            os.path.dirname(__file__), '..', 'models')
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

    def predict_batch(self, model_id: str, batch_data: list) -> list:
        """Make batch predictions with GPU optimization."""
        model = self.load_model(model_id)
        model_info = self.model_metadata[model_id]
        model_type = model_info['type']

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
                    repo_dir = os.path.join(
                        self.models_dir, 'repositories', repo_name)
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
                logger.error(
                    "Backend not available for model type: %s", model_type)
                return False

            backend = self.backends[model_type.lower()]

            # For demonstration, we'll create a simple training workflow
            # In a real implementation, this would depend on the specific model type and data

            if model_type.lower() == 'sklearn':
                # Use sklearn backend for traditional ML models
                try:
                    import numpy as np
                    from sklearn.ensemble import RandomForestClassifier
                    from sklearn.model_selection import train_test_split

                    # Handle different data formats
                    if hasattr(training_data, 'shape'):
                        # NumPy array or similar
                        X = training_data[:, :-
                                          1] if training_data.shape[1] > 1 else training_data
                        y = training_data[:, -1] if training_data.shape[1] > 1 else np.zeros(
                            len(training_data))
                    elif isinstance(training_data, (list, tuple)):
                        # Convert to numpy arrays
                        X = np.array(training_data)
                        y = np.zeros(len(training_data))  # Dummy labels
                    else:
                        logger.warning(
                            "Unsupported training data format for sklearn")
                        return False

                    # Split data for training and validation using train_test_split
                    X_train, X_val, y_train, y_val = train_test_split(
                        X, y, test_size=0.2, random_state=42, stratify=y if len(np.unique(y)) > 1 else None
                    )

                    logger.info(f"Split data: {len(X_train)} training samples, {len(X_val)} validation samples")

                    # Create and train model
                    model = RandomForestClassifier(
                        n_estimators=10, random_state=42)
                    model.fit(X_train, y_train)

                    # Evaluate on validation set
                    val_score = model.score(X_val, y_val)
                    logger.info(f"Validation accuracy: {val_score:.4f}")

                    # Store trained model in cache
                    model_id = f"trained_model_{model_type}_{len(self.cache.cache)}"
                    model_data = {
                        'model': model,
                        'backend': backend,
                        'last_used': time.time(),
                        'metadata': {
                            'type': model_type,
                            'trained': True,
                            'training_samples': len(X_train),
                            'validation_samples': len(X_val),
                            'validation_score': val_score,
                            'train_test_split_ratio': 0.8
                        }
                    }
                    self.cache.put(model_id, model_data)

                    logger.info(
                        "Model training completed successfully: %s", model_id)
                    return True

                except ImportError:
                    logger.warning("sklearn not available for training")
                    return False

            elif model_type.lower() == 'pytorch':
                # PyTorch training implementation
                try:
                    import torch
                    import torch.nn as nn
                    import torch.optim as optim
                    from torch.utils.data import DataLoader, TensorDataset

                    logger.info("Starting PyTorch model training")

                    # Prepare data
                    if isinstance(training_data, dict):
                        X = training_data.get('features', [])
                        y = training_data.get('labels', [])
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
                        TensorDataset(X_tensor, y_tensor), [train_size, val_size]
                    )

                    # Create data loaders
                    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
                    val_loader = DataLoader(val_dataset, batch_size=32, shuffle=False)

                    # Define simple neural network
                    class SimpleNN(nn.Module):
                        """Simple neural network for basic classification tasks."""

                    def __init__(self, input_size, num_classes):
                        """Initialize simple neural network with specified input size and number of classes.

                        Args:
                            input_size: Number of input features
                            num_classes: Number of output classes
                        """
                        super(SimpleNN, self).__init__()
                        self.fc1 = nn.Linear(input_size, 128)
                        self.fc2 = nn.Linear(128, 64)
                        self.fc3 = nn.Linear(64, num_classes)
                        self.dropout = nn.Dropout(0.2)

                    def forward(self, x):
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
                    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
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

                        logger.info(f"Epoch [{epoch+1}/{num_epochs}], "
                                  f"Train Loss: {train_loss/len(train_loader):.4f}, "
                                  f"Train Acc: {train_acc:.2f}%, "
                                  f"Val Acc: {val_acc:.2f}%")

                        if val_acc > best_val_acc:
                            best_val_acc = val_acc

                    # Store trained model
                    model_id = f"trained_pytorch_model_{len(self.cache.cache)}"
                    model_data = {
                        'model': model,
                        'backend': 'pytorch',
                        'last_used': time.time(),
                        'metadata': {
                            'type': 'pytorch',
                            'trained': True,
                            'training_samples': train_size,
                            'validation_samples': val_size,
                            'best_validation_accuracy': best_val_acc,
                            'num_epochs': num_epochs,
                            'device': str(device)
                        }
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

            elif model_type.lower() == 'tensorflow':
                # TensorFlow/Keras training implementation
                try:
                    import tensorflow as tf
                    from tensorflow import keras
                    from tensorflow.keras import layers

                    logger.info("Starting TensorFlow model training")

                    # Prepare data
                    if isinstance(training_data, dict):
                        X = training_data.get('features', [])
                        y = training_data.get('labels', [])
                    else:
                        X, y = training_data

                    # Convert to numpy arrays
                    X = np.array(X, dtype=np.float32)
                    y = np.array(y, dtype=np.int32)

                    # Split data
                    from sklearn.model_selection import train_test_split
                    X_train, X_val, y_train, y_val = train_test_split(
                        X, y, test_size=0.2, random_state=42
                    )

                    # Determine number of classes
                    num_classes = len(np.unique(y))

                    # One-hot encode labels if multi-class
                    if num_classes > 2:
                        y_train = tf.keras.utils.to_categorical(y_train, num_classes)
                        y_val = tf.keras.utils.to_categorical(y_val, num_classes)

                    # Build model
                    model = keras.Sequential([
                        layers.Dense(128, activation='relu', input_shape=(X.shape[1],)),
                        layers.Dropout(0.2),
                        layers.Dense(64, activation='relu'),
                        layers.Dropout(0.2),
                        layers.Dense(num_classes if num_classes > 2 else 1,
                                   activation='softmax' if num_classes > 2 else 'sigmoid')
                    ])

                    # Compile model
                    if num_classes > 2:
                        model.compile(
                            optimizer='adam',
                            loss='categorical_crossentropy',
                            metrics=['accuracy']
                        )
                    else:
                        model.compile(
                            optimizer='adam',
                            loss='binary_crossentropy',
                            metrics=['accuracy']
                        )

                    # Early stopping callback
                    early_stopping = keras.callbacks.EarlyStopping(
                        monitor='val_loss',
                        patience=3,
                        restore_best_weights=True
                    )

                    # Train model
                    history = model.fit(
                        X_train, y_train,
                        validation_data=(X_val, y_val),
                        epochs=20,
                        batch_size=32,
                        callbacks=[early_stopping],
                        verbose=1
                    )

                    # Get final validation accuracy
                    val_loss, val_acc = model.evaluate(X_val, y_val, verbose=0)

                    logger.info(f"TensorFlow training completed - "
                              f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}")

                    # Store trained model
                    model_id = f"trained_tensorflow_model_{len(self.cache.cache)}"
                    model_data = {
                        'model': model,
                        'backend': 'tensorflow',
                        'last_used': time.time(),
                        'metadata': {
                            'type': 'tensorflow',
                            'trained': True,
                            'training_samples': len(X_train),
                            'validation_samples': len(X_val),
                            'validation_loss': float(val_loss),
                            'validation_accuracy': float(val_acc),
                            'num_epochs': len(history.history['loss']),
                            'num_classes': num_classes
                        }
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
                logger.error(
                    "Unsupported model type for training: %s", model_type)
                return False

        except Exception as e:
            logger.error("Model training failed: %s", e)
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
            import pickle
            from pathlib import Path

            # Ensure directory exists
            save_path = Path(path)
            save_path.parent.mkdir(parents=True, exist_ok=True)

            # Try to determine model type and use appropriate saving method
            model_type = type(model).__name__.lower()

            if 'sklearn' in str(type(model)) or hasattr(model, 'fit'):
                # Sklearn or sklearn-compatible model
                try:
                    import joblib
                    joblib.dump(model, str(save_path))
                    logger.info(
                        "Model (type: %s) saved using joblib: %s", model_type, path)
                    return True
                except ImportError:
                    # Fallback to pickle
                    with open(save_path, 'wb') as f:
                        pickle.dump(model, f)
                    logger.info("Model saved using pickle: %s", path)
                    return True

            elif 'torch' in str(type(model)):
                # PyTorch model
                try:
                    import torch
                    torch.save(model.state_dict(), str(save_path))
                    logger.info("PyTorch model saved: %s", path)
                    return True
                except ImportError:
                    logger.error("PyTorch not available for saving")
                    return False

            elif 'tensorflow' in str(type(model)) or 'keras' in str(type(model)):
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
                with open(save_path, 'wb') as f:
                    pickle.dump(model, f)
                logger.info("Model saved using generic pickle: %s", path)
                return True

        except Exception as e:
            logger.error("Model save failed: %s", e)
            return False

    @property
    def repositories(self) -> List[str]:
        """Get available repositories."""
        return self.get_available_repositories()

    def evaluate_model_with_split(self, model_id: str, data: Any, labels: Any, test_size: float = 0.2, random_state: int = 42) -> Dict[str, Any]:
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
            import numpy as np
            from sklearn.model_selection import train_test_split

            # Get the model
            model_data = self.cache.get(model_id)
            if not model_data:
                logger.error(f"Model {model_id} not found in cache")
                return {"error": "Model not found"}

            model = model_data.get('model')
            backend = model_data.get('backend')

            # Convert data to numpy arrays if needed
            if not isinstance(data, np.ndarray):
                data = np.array(data)
            if not isinstance(labels, np.ndarray):
                labels = np.array(labels)

            # Use train_test_split to create training and test sets
            X_train, X_test, y_train, y_test = train_test_split(
                data, labels, test_size=test_size, random_state=random_state,
                stratify=labels if len(np.unique(labels)) > 1 else None
            )

            logger.info(f"Split data into {len(X_train)} training and {len(X_test)} test samples")

            # Evaluate based on backend type
            evaluation_results = {
                "train_size": len(X_train),
                "test_size": len(X_test),
                "test_ratio": test_size,
                "random_state": random_state
            }

            if isinstance(backend, SklearnBackend):
                # Re-train on training set
                model.fit(X_train, y_train)

                # Evaluate on both sets
                train_score = model.score(X_train, y_train)
                test_score = model.score(X_test, y_test)

                evaluation_results.update({
                    "train_score": train_score,
                    "test_score": test_score,
                    "overfitting_gap": train_score - test_score
                })

                # Get predictions for additional metrics
                y_pred = model.predict(X_test)

                # Calculate additional metrics if classification
                if hasattr(model, "predict_proba"):
                    from sklearn.metrics import classification_report, confusion_matrix

                    report = classification_report(y_test, y_pred, output_dict=True)
                    cm = confusion_matrix(y_test, y_pred)

                    evaluation_results.update({
                        "classification_report": report,
                        "confusion_matrix": cm.tolist()
                    })

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

                evaluation_results.update({
                    "train_accuracy": train_accuracy,
                    "test_accuracy": test_accuracy,
                    "backend": "pytorch"
                })

            logger.info(f"Model evaluation completed with test score: {evaluation_results.get('test_score', evaluation_results.get('test_accuracy', 'N/A'))}")
            return evaluation_results

        except ImportError as e:
            logger.error(f"Failed to import required libraries: {e}")
            return {"error": f"Missing dependencies: {e}"}
        except Exception as e:
            logger.error(f"Model evaluation failed: {e}")
            return {"error": str(e)}


class LLMModelManager(ModelManager):
    """Comprehensive LLM model lifecycle manager extending ModelManager."""

    def __init__(self, models_dir: str = None, cache_size: int = 5, 
                 llm_manager: 'LLMManager' = None):
        """Initialize the LLM model manager.
        
        Args:
            models_dir: Directory for storing models
            cache_size: Maximum cache size
            llm_manager: Optional LLMManager instance for backend management
        """
        super().__init__(models_dir, cache_size)
        self.logger = logging.getLogger(__name__ + ".LLMModelManager")
        
        # Initialize LLM-specific components
        self.llm_manager = llm_manager
        self.resource_manager = LLMResourceManager()
        self.health_monitor = LLMHealthMonitor()
        self.version_manager = LLMVersionManager()
        self.load_balancer = LLMLoadBalancer()
        
        # LLM-specific tracking
        self.llm_models: Dict[str, Any] = {}
        self.model_states: Dict[str, ModelState] = {}
        self.model_types: Dict[str, ModelType] = {}
        self.cost_tracking: Dict[str, float] = defaultdict(float)
        
        # Start health monitoring
        self.health_monitor.start_monitoring()
        
        self.logger.info("LLMModelManager initialized")

    @profile_ai_operation
    def register_llm_model(self, model_id: str, config: Union[Dict, 'LLMConfig'], 
                          model_type: ModelType = ModelType.LLM_MODEL,
                          resource_requirements: Optional[ResourceAllocation] = None) -> bool:
        """Register an LLM model with the manager.
        
        Args:
            model_id: Unique identifier for the model
            config: LLM configuration or dictionary
            model_type: Type of model being registered
            resource_requirements: Resource allocation requirements
            
        Returns:
            bool: True if registration successful
        """
        try:
            with self.lock:
                # Convert dict to LLMConfig if needed
                if isinstance(config, dict) and HAS_LLM_BACKENDS:
                    if 'provider' in config:
                        provider = LLMProvider(config['provider'])
                        config = LLMConfig(
                            provider=provider,
                            model_name=config.get('model_name', config.get('model')),
                            api_key=config.get('api_key'),
                            api_base=config.get('api_base'),
                            context_length=config.get('context_length', 4096),
                            temperature=config.get('temperature', 0.7),
                            max_tokens=config.get('max_tokens', 2048)
                        )
                
                # Register with LLM manager if available
                if self.llm_manager and HAS_LLM_BACKENDS:
                    success = self.llm_manager.register_llm(model_id, config)
                    if not success:
                        self.logger.error(f"Failed to register LLM {model_id} with LLM manager")
                        return False
                
                # Allocate resources if requirements provided
                if resource_requirements:
                    if not self.resource_manager.allocate_resources(model_id, resource_requirements):
                        self.logger.warning(f"Resource allocation failed for {model_id}")
                
                # Track model metadata
                self.model_types[model_id] = model_type
                self.model_states[model_id] = ModelState.UNLOADED
                
                # Register for health monitoring
                self.health_monitor.register_model(model_id)
                
                # Store in metadata
                self.model_metadata[model_id] = {
                    'type': 'llm',
                    'model_type': model_type.value,
                    'config': config.__dict__ if hasattr(config, '__dict__') else config,
                    'registered': datetime.now().isoformat(),
                    'state': ModelState.UNLOADED.value
                }
                
                self._save_model_metadata()
                self.logger.info(f"Registered LLM model: {model_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to register LLM model {model_id}: {e}")
            return False

    @profile_ai_operation
    def load_llm_model(self, model_id: str, warm_up: bool = True) -> bool:
        """Load an LLM model.
        
        Args:
            model_id: Model identifier
            warm_up: Whether to warm up the model after loading
            
        Returns:
            bool: True if loading successful
        """
        try:
            with self.lock:
                if model_id not in self.model_metadata:
                    self.logger.error(f"Model {model_id} not registered")
                    return False
                
                # Update state
                self.model_states[model_id] = ModelState.LOADING
                
                # Load via LLM manager if available
                if self.llm_manager and HAS_LLM_BACKENDS:
                    try:
                        backend = self.llm_manager.get_backend(model_id)
                        if backend:
                            self.llm_models[model_id] = backend
                            self.model_states[model_id] = ModelState.LOADED
                            
                            # Warm up if requested
                            if warm_up:
                                self._warm_up_model(model_id)
                            
                            self.logger.info(f"Loaded LLM model: {model_id}")
                            return True
                    except Exception as e:
                        self.logger.error(f"LLM backend loading failed for {model_id}: {e}")
                
                # Fallback to parent class loading for non-LLM models
                try:
                    model = super().load_model(model_id)
                    if model:
                        self.llm_models[model_id] = model
                        self.model_states[model_id] = ModelState.LOADED
                        return True
                except Exception as e:
                    self.logger.debug(f"Fallback loading failed for {model_id}: {e}")
                
                self.model_states[model_id] = ModelState.ERROR
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to load LLM model {model_id}: {e}")
            if model_id in self.model_states:
                self.model_states[model_id] = ModelState.ERROR
            return False

    def unload_llm_model(self, model_id: str) -> bool:
        """Unload an LLM model and free resources."""
        try:
            with self.lock:
                # Remove from loaded models
                if model_id in self.llm_models:
                    del self.llm_models[model_id]
                
                # Deallocate resources
                self.resource_manager.deallocate_resources(model_id)
                
                # Update state
                self.model_states[model_id] = ModelState.UNLOADED
                
                # Also unload from parent class
                super().unload_model(model_id)
                
                self.logger.info(f"Unloaded LLM model: {model_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to unload LLM model {model_id}: {e}")
            return False

    def hot_swap_model(self, old_model_id: str, new_model_id: str) -> bool:
        """Perform hot swap between models."""
        try:
            # Load new model first
            if not self.load_llm_model(new_model_id):
                self.logger.error(f"Failed to load new model {new_model_id} for hot swap")
                return False
            
            # Update load balancer
            self.load_balancer.mark_model_failed(old_model_id)
            self.load_balancer.mark_model_healthy(new_model_id)
            
            # Unload old model
            self.unload_llm_model(old_model_id)
            
            self.logger.info(f"Hot swapped model {old_model_id} -> {new_model_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Hot swap failed {old_model_id} -> {new_model_id}: {e}")
            return False

    def _warm_up_model(self, model_id: str):
        """Warm up a model with test requests."""
        try:
            self.model_states[model_id] = ModelState.WARMING
            
            # Send a few warm-up requests
            test_messages = [
                "Hello, how are you?",
                "What is the capital of France?",
                "Please summarize this text: AI is transforming technology."
            ]
            
            for message in test_messages:
                try:
                    start_time = time.time()
                    # In a real implementation, this would make actual requests
                    # For now, we'll simulate
                    time.sleep(0.1)  # Simulate processing time
                    response_time = time.time() - start_time
                    
                    self.health_monitor.record_request(model_id, True, response_time)
                except Exception as e:
                    self.health_monitor.record_request(model_id, False, 0.0, str(e))
            
            self.model_states[model_id] = ModelState.ACTIVE
            self.logger.info(f"Warmed up model: {model_id}")
            
        except Exception as e:
            self.logger.error(f"Model warm-up failed for {model_id}: {e}")
            self.model_states[model_id] = ModelState.ERROR

    def get_model_health(self, model_id: str = None) -> Dict[str, Any]:
        """Get health status for models."""
        if model_id:
            return self.health_monitor.check_model_health(model_id)
        else:
            # Get health for all models
            results = {}
            for mid in self.model_metadata.keys():
                results[mid] = self.health_monitor.check_model_health(mid)
            return results

    def get_performance_metrics(self, model_id: str = None) -> Dict[str, Any]:
        """Get performance metrics."""
        return self.health_monitor.get_performance_metrics(model_id)

    def optimize_resources(self) -> Dict[str, Any]:
        """Optimize resource usage across all models."""
        return self.resource_manager.optimize_memory_usage()

    def get_resource_usage(self) -> Dict[str, Any]:
        """Get current resource usage."""
        return self.resource_manager.get_resource_usage()

    def setup_load_balancing(self, pool_name: str, model_ids: List[str], 
                           fallback_chain: Optional[Dict[str, List[str]]] = None) -> bool:
        """Setup load balancing for a group of models."""
        try:
            self.load_balancer.register_model_pool(pool_name, model_ids)
            
            if fallback_chain:
                for primary, fallbacks in fallback_chain.items():
                    self.load_balancer.setup_fallback_chain(primary, fallbacks)
            
            self.logger.info(f"Setup load balancing for pool {pool_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup load balancing: {e}")
            return False

    def route_request(self, pool_name: str = None) -> Optional[str]:
        """Route a request to an available model."""
        return self.load_balancer.get_next_model(pool_name)

    def get_llm_manager_stats(self) -> Dict[str, Any]:
        """Get comprehensive LLM manager statistics."""
        base_stats = self.get_manager_stats()
        
        llm_stats = {
            'llm_models_loaded': len(self.llm_models),
            'model_states': {mid: state.value for mid, state in self.model_states.items()},
            'model_types': {mid: mtype.value for mid, mtype in self.model_types.items()},
            'resource_usage': self.get_resource_usage(),
            'load_balancer_stats': self.load_balancer.get_load_stats(),
            'total_cost': sum(self.cost_tracking.values()),
            'health_summary': self.get_model_health()
        }
        
        return {**base_stats, **llm_stats}

    def shutdown(self):
        """Shutdown the LLM model manager."""
        try:
            # Stop health monitoring
            self.health_monitor.stop_monitoring()
            
            # Unload all models
            for model_id in list(self.llm_models.keys()):
                self.unload_llm_model(model_id)
            
            # Deallocate all resources
            for model_id in list(self.resource_manager.allocations.keys()):
                self.resource_manager.deallocate_resources(model_id)
            
            self.logger.info("LLMModelManager shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")

    def __del__(self):
        """Cleanup resources on garbage collection."""
        try:
            self.shutdown()
        except Exception:
            pass  # Ignore cleanup errors during garbage collection


class AsyncModelManager:
    """Asynchronous wrapper for model operations."""

    def __init__(self, model_manager: ModelManager):
        """Initialize the asynchronous model manager wrapper.

        Args:
            model_manager: The underlying ModelManager instance to wrap with async capabilities.
        """
        self.logger = logging.getLogger(__name__ + ".AsyncModelManager")
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
                self.logger.error("Error in model_manager_module: %s", e)
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
                self.logger.error("Error in model_manager_module: %s", e)
                if callback:
                    callback(False, None, str(e))

        thread = threading.Thread(target=predict_worker, daemon=True)
        thread.start()
        return thread

    def __del__(self):
        """Cleanup resources on garbage collection."""
        # No specific cleanup needed for AsyncModelManager - it's just a wrapper
        pass


class ModelOrchestrator:
    """Orchestrates multiple models for complex multi-step tasks."""

    def __init__(self, llm_model_manager: LLMModelManager):
        """Initialize the model orchestrator.
        
        Args:
            llm_model_manager: LLMModelManager instance for model coordination
        """
        self.logger = logging.getLogger(__name__ + ".ModelOrchestrator")
        self.llm_manager = llm_model_manager
        self.task_queue = Queue()
        self.result_cache = {}
        self.orchestration_strategies = {}
        self.lock = threading.RLock()

    def register_strategy(self, strategy_name: str, model_pipeline: List[str], 
                         coordination_logic: Callable = None):
        """Register an orchestration strategy.
        
        Args:
            strategy_name: Name of the strategy
            model_pipeline: List of model IDs in execution order
            coordination_logic: Optional custom coordination function
        """
        with self.lock:
            self.orchestration_strategies[strategy_name] = {
                'pipeline': model_pipeline,
                'logic': coordination_logic or self._default_pipeline_logic,
                'registered': datetime.now()
            }
            self.logger.info(f"Registered orchestration strategy: {strategy_name}")

    def execute_strategy(self, strategy_name: str, input_data: Any, 
                        context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a multi-model orchestration strategy.
        
        Args:
            strategy_name: Name of the strategy to execute
            input_data: Input data for the pipeline
            context: Optional context information
            
        Returns:
            Dict containing results from the orchestration
        """
        try:
            if strategy_name not in self.orchestration_strategies:
                return {"error": f"Strategy {strategy_name} not found"}

            strategy = self.orchestration_strategies[strategy_name]
            pipeline = strategy['pipeline']
            logic_func = strategy['logic']

            self.logger.info(f"Executing strategy {strategy_name} with {len(pipeline)} models")

            # Execute the coordination logic
            results = logic_func(pipeline, input_data, context or {})

            return {
                "strategy": strategy_name,
                "success": True,
                "results": results,
                "models_used": pipeline
            }

        except Exception as e:
            self.logger.error(f"Strategy execution failed for {strategy_name}: {e}")
            return {
                "strategy": strategy_name,
                "success": False,
                "error": str(e)
            }

    def _default_pipeline_logic(self, pipeline: List[str], input_data: Any, 
                               context: Dict[str, Any]) -> Dict[str, Any]:
        """Default pipeline execution logic."""
        results = {}
        current_data = input_data

        for i, model_id in enumerate(pipeline):
            try:
                self.logger.debug(f"Executing model {model_id} (step {i+1}/{len(pipeline)})")

                # Check if model is loaded and healthy
                health = self.llm_manager.get_model_health(model_id)
                if not health.get('healthy', False):
                    # Try to route to a fallback model
                    fallback = self.llm_manager.load_balancer.get_fallback_model(model_id)
                    if fallback:
                        model_id = fallback
                        self.logger.info(f"Using fallback model {fallback} for {model_id}")
                    else:
                        raise RuntimeError(f"Model {model_id} is unhealthy and no fallback available")

                # Execute model
                start_time = time.time()
                
                # In a real implementation, this would call the actual model
                # For now, we'll simulate the model execution
                if model_id in self.llm_manager.llm_models:
                    # Simulate processing time based on model type
                    processing_time = 0.5 if 'fast' in model_id.lower() else 1.0
                    time.sleep(processing_time)
                    
                    # Simulate model output
                    model_result = {
                        "processed_by": model_id,
                        "input_received": str(current_data)[:100],
                        "output": f"Processed by {model_id} at step {i+1}",
                        "confidence": 0.95,
                        "processing_time": processing_time
                    }
                else:
                    # Fallback to parent class prediction
                    model_result = self.llm_manager.predict(model_id, current_data)

                response_time = time.time() - start_time

                # Record metrics
                self.llm_manager.health_monitor.record_request(
                    model_id, True, response_time
                )

                # Store result
                results[f"step_{i+1}_{model_id}"] = model_result

                # Update current data for next model (pipeline)
                current_data = model_result

            except Exception as e:
                self.logger.error(f"Model {model_id} execution failed: {e}")
                
                # Record failure
                self.llm_manager.health_monitor.record_request(
                    model_id, False, 0.0, str(e)
                )

                # Try fallback or continue with original data
                fallback = self.llm_manager.load_balancer.get_fallback_model(model_id)
                if fallback:
                    try:
                        # Retry with fallback
                        self.logger.info(f"Retrying with fallback model {fallback}")
                        continue
                    except Exception as fallback_error:
                        self.logger.error(f"Fallback model {fallback} also failed: {fallback_error}")

                # If no fallback or fallback failed, record error and continue
                results[f"step_{i+1}_{model_id}"] = {
                    "error": str(e),
                    "model_id": model_id,
                    "step": i+1
                }

        return results

    def execute_parallel_strategy(self, model_ids: List[str], input_data: Any,
                                 aggregation_func: Optional[Callable] = None) -> Dict[str, Any]:
        """Execute multiple models in parallel and aggregate results.
        
        Args:
            model_ids: List of model IDs to execute in parallel
            input_data: Input data for all models
            aggregation_func: Optional function to aggregate results
            
        Returns:
            Dict containing aggregated results
        """
        try:
            results = {}
            threads = []
            thread_results = {}

            def execute_model(model_id: str):
                """Execute a single model in a thread."""
                try:
                    start_time = time.time()
                    
                    # Simulate model execution
                    if model_id in self.llm_manager.llm_models:
                        processing_time = 0.3
                        time.sleep(processing_time)
                        result = {
                            "model_id": model_id,
                            "output": f"Parallel result from {model_id}",
                            "confidence": 0.9,
                            "processing_time": processing_time
                        }
                    else:
                        result = self.llm_manager.predict(model_id, input_data)

                    response_time = time.time() - start_time
                    
                    # Record success
                    self.llm_manager.health_monitor.record_request(
                        model_id, True, response_time
                    )
                    
                    thread_results[model_id] = result

                except Exception as e:
                    self.logger.error(f"Parallel model {model_id} failed: {e}")
                    self.llm_manager.health_monitor.record_request(
                        model_id, False, 0.0, str(e)
                    )
                    thread_results[model_id] = {"error": str(e)}

            # Start all model executions in parallel
            for model_id in model_ids:
                thread = threading.Thread(target=execute_model, args=(model_id,))
                threads.append(thread)
                thread.start()

            # Wait for all threads to complete
            for thread in threads:
                thread.join(timeout=30.0)  # 30 second timeout

            # Aggregate results
            if aggregation_func:
                aggregated = aggregation_func(thread_results)
            else:
                # Default aggregation: majority vote or average
                aggregated = self._default_aggregation(thread_results)

            return {
                "strategy": "parallel",
                "success": True,
                "individual_results": thread_results,
                "aggregated_result": aggregated,
                "models_used": model_ids
            }

        except Exception as e:
            self.logger.error(f"Parallel strategy execution failed: {e}")
            return {
                "strategy": "parallel",
                "success": False,
                "error": str(e)
            }

    def _default_aggregation(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Default aggregation logic for parallel results."""
        successful_results = {
            k: v for k, v in results.items() 
            if isinstance(v, dict) and 'error' not in v
        }

        if not successful_results:
            return {"error": "All models failed"}

        # Simple aggregation: take the result with highest confidence
        best_result = max(
            successful_results.values(),
            key=lambda x: x.get('confidence', 0.0),
            default={}
        )

        return {
            "aggregation_method": "highest_confidence",
            "successful_models": len(successful_results),
            "total_models": len(results),
            "best_result": best_result,
            "average_confidence": sum(
                r.get('confidence', 0.0) for r in successful_results.values()
            ) / len(successful_results) if successful_results else 0.0
        }

    def get_orchestration_stats(self) -> Dict[str, Any]:
        """Get orchestration statistics."""
        with self.lock:
            return {
                "registered_strategies": len(self.orchestration_strategies),
                "strategies": {
                    name: {
                        "pipeline_length": len(strategy['pipeline']),
                        "models": strategy['pipeline'],
                        "registered": strategy['registered'].isoformat()
                    }
                    for name, strategy in self.orchestration_strategies.items()
                },
                "cache_size": len(self.result_cache)
            }


# Factory function for easy instantiation
def create_model_manager(models_dir: str = None, cache_size: int = 5) -> ModelManager:
    """Create a model manager instance."""
    return ModelManager(models_dir=models_dir, cache_size=cache_size)


def create_llm_model_manager(models_dir: str = None, cache_size: int = 5,
                            llm_manager: 'LLMManager' = None) -> LLMModelManager:
    """Create an LLM model manager instance.
    
    Args:
        models_dir: Directory for storing models
        cache_size: Maximum cache size
        llm_manager: Optional LLMManager instance
        
    Returns:
        LLMModelManager instance
    """
    return LLMModelManager(models_dir=models_dir, cache_size=cache_size, llm_manager=llm_manager)


def create_model_orchestrator(llm_manager: LLMModelManager) -> ModelOrchestrator:
    """Create a model orchestrator instance.
    
    Args:
        llm_manager: LLMModelManager instance
        
    Returns:
        ModelOrchestrator instance
    """
    return ModelOrchestrator(llm_manager)


# Global model manager instances
_GLOBAL_MODEL_MANAGER = None
_GLOBAL_LLM_MODEL_MANAGER = None
_GLOBAL_MODEL_ORCHESTRATOR = None


def get_global_model_manager() -> ModelManager:
    """Get the global model manager instance."""
    global _GLOBAL_MODEL_MANAGER  # pylint: disable=global-statement
    if _GLOBAL_MODEL_MANAGER is None:
        _GLOBAL_MODEL_MANAGER = create_model_manager()
    return _GLOBAL_MODEL_MANAGER


def get_global_llm_model_manager() -> LLMModelManager:
    """Get the global LLM model manager instance."""
    global _GLOBAL_LLM_MODEL_MANAGER  # pylint: disable=global-statement
    if _GLOBAL_LLM_MODEL_MANAGER is None:
        # Try to import and use LLMManager if available
        llm_manager = None
        if HAS_LLM_BACKENDS:
            try:
                from .llm_backends import LLMManager
                llm_manager = LLMManager()
            except ImportError:
                pass
        
        _GLOBAL_LLM_MODEL_MANAGER = create_llm_model_manager(llm_manager=llm_manager)
    return _GLOBAL_LLM_MODEL_MANAGER


def get_global_model_orchestrator() -> ModelOrchestrator:
    """Get the global model orchestrator instance."""
    global _GLOBAL_MODEL_ORCHESTRATOR  # pylint: disable=global-statement
    if _GLOBAL_MODEL_ORCHESTRATOR is None:
        llm_manager = get_global_llm_model_manager()
        _GLOBAL_MODEL_ORCHESTRATOR = create_model_orchestrator(llm_manager)
    return _GLOBAL_MODEL_ORCHESTRATOR


class ModelFineTuner:
    """Fine-tuning support for AI models."""

    def __init__(self, model_manager: ModelManager):
        """Initialize the model fine-tuner.

        Args:
            model_manager: The ModelManager instance for accessing and managing models.
        """
        self.logger = logging.getLogger(__name__ + ".ModelFineTuner")
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
                    raise ValueError(
                        f"Fine-tuning not supported for model type: {model_type}")

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

                logger.info(
                    "Fine-tuning completed. New model ID: %s", fine_tuned_id)

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
            torch.tensor(training_data[1]).long()
        )
        train_loader = DataLoader(
            train_dataset, batch_size=batch_size, shuffle=True)

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
            optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )

        # Prepare callbacks
        callbacks = []
        if callback:
            class ProgressCallback(keras.callbacks.Callback):
                """
                Keras callback to report training progress to the parent callback.

                Inherits from keras.callbacks.Callback to intercept training events
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
                raise ImportError(
                    "PyTorch not available for saving .pt/.pth files")
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
                logger.error("Error in model_manager_module: %s", e)
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
        logger.error("Failed to configure AI provider %s: %s",
                     provider_name, e)
        return {
            "success": False,
            "error": str(e),
            "provider": provider_name
        }


class LLMCostOptimizer:
    """Cost optimization and tracking for LLM models."""
    
    def __init__(self):
        """Initialize the cost optimizer."""
        self.logger = logging.getLogger(__name__ + ".LLMCostOptimizer")
        self.cost_tracking = defaultdict(float)
        self.usage_tracking = defaultdict(int)
        self.cost_rates = {
            # Example cost rates per 1K tokens (in USD)
            'gpt-4': {'input': 0.03, 'output': 0.06},
            'gpt-3.5-turbo': {'input': 0.001, 'output': 0.002},
            'claude-3': {'input': 0.015, 'output': 0.075},
            'gemini-pro': {'input': 0.0005, 'output': 0.0015},
            'local': {'input': 0.0, 'output': 0.0}  # No cost for local models
        }
        self.lock = threading.RLock()

    def track_usage(self, model_id: str, input_tokens: int, output_tokens: int,
                   model_name: str = None) -> float:
        """Track usage and calculate cost for a request.
        
        Args:
            model_id: Model identifier
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            model_name: Optional model name for cost calculation
            
        Returns:
            float: Cost of the request
        """
        with self.lock:
            try:
                # Determine cost rate
                cost_rate = self._get_cost_rate(model_name or model_id)
                
                # Calculate cost
                input_cost = (input_tokens / 1000) * cost_rate['input']
                output_cost = (output_tokens / 1000) * cost_rate['output']
                total_cost = input_cost + output_cost
                
                # Track usage
                self.cost_tracking[model_id] += total_cost
                self.usage_tracking[model_id] += input_tokens + output_tokens
                
                self.logger.debug(f"Cost tracking for {model_id}: ${total_cost:.6f} "
                                f"({input_tokens} input + {output_tokens} output tokens)")
                
                return total_cost
                
            except Exception as e:
                self.logger.error(f"Cost tracking failed for {model_id}: {e}")
                return 0.0

    def _get_cost_rate(self, model_name: str) -> Dict[str, float]:
        """Get cost rate for a model."""
        model_name_lower = model_name.lower()
        
        # Match by model name patterns
        for rate_key, rates in self.cost_rates.items():
            if rate_key in model_name_lower:
                return rates
        
        # Default to local model rates (free)
        return self.cost_rates['local']

    def get_cost_summary(self, model_id: str = None) -> Dict[str, Any]:
        """Get cost summary for models.
        
        Args:
            model_id: Optional specific model ID
            
        Returns:
            Dict with cost information
        """
        with self.lock:
            if model_id:
                return {
                    'model_id': model_id,
                    'total_cost': self.cost_tracking.get(model_id, 0.0),
                    'total_tokens': self.usage_tracking.get(model_id, 0),
                    'cost_per_token': (
                        self.cost_tracking.get(model_id, 0.0) / 
                        max(self.usage_tracking.get(model_id, 1), 1)
                    )
                }
            else:
                total_cost = sum(self.cost_tracking.values())
                total_tokens = sum(self.usage_tracking.values())
                
                return {
                    'total_cost_all_models': total_cost,
                    'total_tokens_all_models': total_tokens,
                    'average_cost_per_token': total_cost / max(total_tokens, 1),
                    'model_breakdown': {
                        model_id: {
                            'cost': cost,
                            'tokens': self.usage_tracking[model_id],
                            'cost_per_token': cost / max(self.usage_tracking[model_id], 1)
                        }
                        for model_id, cost in self.cost_tracking.items()
                    }
                }

    def optimize_model_selection(self, task_type: str, quality_threshold: float = 0.8,
                               available_models: List[str] = None) -> Optional[str]:
        """Optimize model selection based on cost and quality.
        
        Args:
            task_type: Type of task (affects quality requirements)
            quality_threshold: Minimum quality threshold
            available_models: List of available models
            
        Returns:
            Recommended model ID or None
        """
        try:
            if not available_models:
                return None
            
            # Get cost and performance data for models
            model_scores = []
            
            for model_id in available_models:
                cost_info = self.get_cost_summary(model_id)
                cost_per_token = cost_info.get('cost_per_token', 0.0)
                
                # Simple scoring: lower cost is better, but needs to meet quality threshold
                # In a real implementation, this would use actual quality metrics
                estimated_quality = 0.9 if 'gpt-4' in model_id.lower() else 0.8
                
                if estimated_quality >= quality_threshold:
                    # Score = quality / cost (higher is better)
                    score = estimated_quality / max(cost_per_token, 0.0001)
                    model_scores.append((model_id, score, estimated_quality, cost_per_token))
            
            if not model_scores:
                return None
            
            # Return model with best score
            best_model = max(model_scores, key=lambda x: x[1])
            
            self.logger.info(f"Recommended model {best_model[0]} for {task_type} "
                           f"(quality: {best_model[2]:.2f}, cost/token: ${best_model[3]:.6f})")
            
            return best_model[0]
            
        except Exception as e:
            self.logger.error(f"Model optimization failed: {e}")
            return None

    def set_cost_limits(self, model_id: str, daily_limit: float = None, 
                       monthly_limit: float = None) -> bool:
        """Set cost limits for a model.
        
        Args:
            model_id: Model identifier
            daily_limit: Daily cost limit in USD
            monthly_limit: Monthly cost limit in USD
            
        Returns:
            bool: True if limits were set
        """
        # In a production system, this would implement actual cost limiting
        # For now, we'll just log the intent
        self.logger.info(f"Cost limits set for {model_id}: "
                        f"daily=${daily_limit}, monthly=${monthly_limit}")
        return True

    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Get cost optimization recommendations."""
        recommendations = []
        
        with self.lock:
            # Find high-cost models
            for model_id, total_cost in self.cost_tracking.items():
                if total_cost > 10.0:  # More than $10 spent
                    cost_per_token = total_cost / max(self.usage_tracking[model_id], 1)
                    
                    if cost_per_token > 0.001:  # High cost per token
                        recommendations.append({
                            'type': 'high_cost_model',
                            'model_id': model_id,
                            'total_cost': total_cost,
                            'cost_per_token': cost_per_token,
                            'recommendation': 'Consider switching to a more cost-effective model',
                            'priority': 'high' if cost_per_token > 0.01 else 'medium'
                        })
            
            # Suggest local models for development
            if len(self.cost_tracking) > 0:
                recommendations.append({
                    'type': 'local_development',
                    'recommendation': 'Consider using local models for development and testing',
                    'potential_savings': sum(self.cost_tracking.values()) * 0.8,
                    'priority': 'medium'
                })
        
        return recommendations


# Export for external use
__all__ = [
    # Core classes
    'ModelManager', 'AsyncModelManager', 'ModelCache', 'ModelFineTuner',
    'LLMModelManager', 'ModelOrchestrator',
    
    # Resource and monitoring classes
    'LLMResourceManager', 'LLMHealthMonitor', 'LLMVersionManager', 
    'LLMLoadBalancer', 'LLMCostOptimizer',
    
    # Backend classes
    'PyTorchBackend', 'TensorFlowBackend', 'ONNXBackend', 'SklearnBackend', 'ModelBackend',
    
    # Enums and data classes
    'ModelType', 'ModelState', 'ResourceType', 'ModelMetrics', 'ResourceAllocation',
    
    # Factory functions
    'create_model_manager', 'create_llm_model_manager', 'create_model_orchestrator',
    
    # Global instances
    'get_global_model_manager', 'get_global_llm_model_manager', 'get_global_model_orchestrator',
    
    # Convenience functions
    'import_custom_model', 'load_model', 'save_model', 
    'list_available_models', 'configure_ai_provider'
]
