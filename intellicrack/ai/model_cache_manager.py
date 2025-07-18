"""
Model Cache Manager for Intellicrack

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

import gc
import json
import pickle
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..utils.logger import get_logger

# Try to import GPU autoloader
GPU_AUTOLOADER_AVAILABLE = False
get_device = None
get_gpu_info = None
to_device = None
memory_allocated = None
memory_reserved = None
import hashlib
import hmac
import os

# Security configuration for pickle
PICKLE_SECURITY_KEY = os.environ.get('INTELLICRACK_PICKLE_KEY', 'default-key-change-me').encode()

def secure_pickle_dump(obj, file_path):
    """Securely dump object with integrity check."""
    # Serialize object
    data = pickle.dumps(obj)

    # Calculate HMAC for integrity
    mac = hmac.new(PICKLE_SECURITY_KEY, data, hashlib.sha256).digest()

    # Write MAC + data
    with open(file_path, 'wb') as f:
        f.write(mac)
        f.write(data)

def secure_pickle_load(file_path):
    """Securely load object with integrity verification."""
    with open(file_path, 'rb') as f:
        # Read MAC
        stored_mac = f.read(32)  # SHA256 produces 32 bytes
        data = f.read()

    # Verify integrity
    expected_mac = hmac.new(PICKLE_SECURITY_KEY, data, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        raise ValueError("Pickle file integrity check failed - possible tampering detected")

    # Load object
    return pickle.loads(data)
empty_cache = None
gpu_autoloader = None

try:
    from ..utils.gpu_autoloader import (
        empty_cache,
        get_device,
        get_gpu_info,
        gpu_autoloader,
        memory_allocated,
        memory_reserved,
        to_device,
    )
    GPU_AUTOLOADER_AVAILABLE = True
except ImportError:
    pass

try:
    import torch
    HAS_TORCH = True
except ImportError:
    torch = None
    HAS_TORCH = False

logger = get_logger(__name__)


@dataclass
class CacheEntry:
    """Information about a cached model."""
    model_id: str
    model_type: str  # "pytorch", "tensorflow", "onnx", etc.
    model_object: Any
    tokenizer_object: Optional[Any]
    config: Dict[str, Any]
    memory_size: int  # bytes
    last_accessed: datetime
    access_count: int
    load_time: float  # seconds
    device: str
    quantization: Optional[str] = None
    adapter_info: Optional[Dict[str, Any]] = None


class ModelCacheManager:
    """Manages in-memory caching of loaded models."""

    def __init__(
        self,
        max_memory_gb: float = 8.0,
        cache_dir: Optional[str] = None,
        enable_disk_cache: bool = True
    ):
        """Initialize the model cache manager.

        Args:
            max_memory_gb: Maximum memory to use for caching (GB)
            cache_dir: Directory for disk-based cache
            enable_disk_cache: Whether to enable disk caching
        """
        self.max_memory_bytes = int(max_memory_gb * 1024 * 1024 * 1024)
        self.enable_disk_cache = enable_disk_cache

        if cache_dir is None:
            cache_dir = Path.home() / ".intellicrack" / "model_memory_cache"

        self.cache_dir = Path(cache_dir)
        if self.enable_disk_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

        # In-memory cache (LRU)
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.current_memory_usage = 0

        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "total_load_time": 0.0
        }

        # Disk cache index
        self.disk_index_file = self.cache_dir / "index.json"
        self.disk_index = self._load_disk_index()

    def _load_disk_index(self) -> Dict[str, Any]:
        """Load disk cache index."""
        if not self.enable_disk_cache or not self.disk_index_file.exists():
            return {}

        try:
            with open(self.disk_index_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load disk cache index: {e}")
            return {}

    def _save_disk_index(self):
        """Save disk cache index."""
        if not self.enable_disk_cache:
            return

        try:
            with open(self.disk_index_file, 'w') as f:
                json.dump(self.disk_index, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save disk cache index: {e}")

    def _estimate_model_memory(self, model: Any) -> int:
        """Estimate memory usage of a model.

        Args:
            model: Model object

        Returns:
            Estimated memory in bytes
        """
        total_size = 0

        try:
            # For PyTorch models
            if hasattr(model, 'parameters'):
                for param in model.parameters():
                    if hasattr(param, 'nelement') and hasattr(param, 'element_size'):
                        total_size += param.nelement() * param.element_size()
                    elif hasattr(param, 'data'):
                        if hasattr(param.data, 'nbytes'):
                            total_size += param.data.nbytes
                        else:
                            # Estimate based on shape and dtype
                            total_size += param.data.numel() * param.data.element_size()

            # For TensorFlow models
            elif hasattr(model, 'variables'):
                for var in model.variables:
                    if hasattr(var, 'numpy'):
                        total_size += var.numpy().nbytes

            # For ONNX models (rough estimate)
            elif hasattr(model, 'graph'):
                # Estimate based on graph complexity
                total_size = 100 * 1024 * 1024  # 100MB default

            # Add overhead (buffers, gradients, etc.)
            total_size = int(total_size * 1.5)

        except Exception as e:
            logger.warning(f"Could not estimate model memory: {e}")
            # Default estimate
            total_size = 500 * 1024 * 1024  # 500MB

        return total_size

    def get(
        self,
        model_id: str,
        load_function: Optional[callable] = None
    ) -> Optional[Tuple[Any, Optional[Any]]]:
        """Get a model from cache or load it.

        Args:
            model_id: Unique identifier for the model
            load_function: Function to load the model if not cached

        Returns:
            Tuple of (model, tokenizer) or None
        """
        # Check in-memory cache
        if model_id in self.cache:
            # Move to end (LRU)
            entry = self.cache.pop(model_id)
            entry.last_accessed = datetime.now()
            entry.access_count += 1
            self.cache[model_id] = entry

            self.stats["hits"] += 1
            logger.info(f"Cache hit for model: {model_id}")

            return entry.model_object, entry.tokenizer_object

        self.stats["misses"] += 1

        # Check disk cache
        if self.enable_disk_cache and model_id in self.disk_index:
            loaded = self._load_from_disk(model_id)
            if loaded:
                return loaded

        # Load using provided function
        if load_function:
            start_time = time.time()

            try:
                result = load_function()
                if result is None:
                    return None

                # Handle different return types
                if isinstance(result, tuple):
                    model, tokenizer = result[0], result[1] if len(
                        result) > 1 else None
                else:
                    model, tokenizer = result, None

                load_time = time.time() - start_time
                self.stats["total_load_time"] += load_time

                # Cache the model
                self.put(
                    model_id=model_id,
                    model=model,
                    tokenizer=tokenizer,
                    load_time=load_time
                )

                return model, tokenizer

            except Exception as e:
                logger.error(f"Failed to load model {model_id}: {e}")
                return None

        return None

    def put(
        self,
        model_id: str,
        model: Any,
        tokenizer: Optional[Any] = None,
        model_type: str = "auto",
        config: Optional[Dict[str, Any]] = None,
        load_time: float = 0.0,
        **kwargs
    ):
        """Add a model to the cache.

        Args:
            model_id: Unique identifier
            model: Model object
            tokenizer: Optional tokenizer
            model_type: Type of model
            config: Model configuration
            load_time: Time taken to load
            **kwargs: Additional metadata
        """
        # Auto-detect model type
        if model_type == "auto":
            if hasattr(model, 'forward') and hasattr(model, 'parameters'):
                model_type = "pytorch"
            elif hasattr(model, 'predict') and hasattr(model, 'variables'):
                model_type = "tensorflow"
            elif hasattr(model, 'run'):
                model_type = "onnx"
            else:
                model_type = "unknown"

        # Estimate memory usage
        memory_size = self._estimate_model_memory(model)

        # Check if we need to evict models
        while (self.current_memory_usage + memory_size > self.max_memory_bytes
               and len(self.cache) > 0):
            self._evict_lru()

        # Detect device
        device = "cpu"
        if GPU_AUTOLOADER_AVAILABLE:
            device = get_device()
        elif hasattr(model, 'device'):
            device = str(model.device)
        elif hasattr(model, 'module') and hasattr(model.module, 'device'):
            device = str(model.module.device)

        # Create cache entry
        entry = CacheEntry(
            model_id=model_id,
            model_type=model_type,
            model_object=model,
            tokenizer_object=tokenizer,
            config=config or {},
            memory_size=memory_size,
            last_accessed=datetime.now(),
            access_count=1,
            load_time=load_time,
            device=device,
            quantization=kwargs.get("quantization"),
            adapter_info=kwargs.get("adapter_info")
        )

        # Add to cache
        self.cache[model_id] = entry
        self.current_memory_usage += memory_size

        # Apply GPU optimization if available
        if GPU_AUTOLOADER_AVAILABLE and gpu_autoloader and entry.device != "cpu":
            try:
                # Apply GPU optimizations to the model
                optimized_model = gpu_autoloader(model)
                if optimized_model is not None:
                    entry.model_object = optimized_model
                    logger.info(f"Applied GPU optimizations to model: {model_id}")
            except Exception as e:
                logger.debug(f"Could not apply GPU optimizations: {e}")

        logger.info(
            f"Cached model {model_id}: {memory_size / (1024**2):.1f}MB, "
            f"total cache: {self.current_memory_usage / (1024**2):.1f}MB"
        )

    def _evict_lru(self):
        """Evict least recently used model."""
        if not self.cache:
            return

        # Get oldest entry
        model_id, entry = next(iter(self.cache.items()))

        # Save to disk if enabled
        if self.enable_disk_cache:
            self._save_to_disk(model_id, entry)

        # Remove from memory
        del self.cache[model_id]
        self.current_memory_usage -= entry.memory_size
        self.stats["evictions"] += 1

        # Clean up GPU memory if applicable
        if entry.device != "cpu":
            if GPU_AUTOLOADER_AVAILABLE and empty_cache:
                empty_cache()
            elif HAS_TORCH and torch.cuda.is_available():
                torch.cuda.empty_cache()
        gc.collect()

        logger.info(f"Evicted model from cache: {model_id}")

    def _save_to_disk(self, model_id: str, entry: CacheEntry) -> bool:
        """Save model to disk cache.

        Args:
            model_id: Model identifier
            entry: Cache entry

        Returns:
            True if saved successfully
        """
        if not self.enable_disk_cache:
            return False

        try:
            # Create model directory
            model_dir = self.cache_dir / model_id.replace("/", "_")
            model_dir.mkdir(parents=True, exist_ok=True)

            # Save model
            model_path = model_dir / "model.pkl"
            secure_pickle_dump(entry.model_object, model_path)

            # Save tokenizer if present
            if entry.tokenizer_object:
                tokenizer_path = model_dir / "tokenizer.pkl"
                secure_pickle_dump(entry.tokenizer_object, tokenizer_path)

            # Save metadata
            metadata = {
                "model_id": entry.model_id,
                "model_type": entry.model_type,
                "config": entry.config,
                "memory_size": entry.memory_size,
                "last_accessed": entry.last_accessed.isoformat(),
                "access_count": entry.access_count,
                "load_time": entry.load_time,
                "device": entry.device,
                "quantization": entry.quantization,
                "adapter_info": entry.adapter_info,
                "has_tokenizer": entry.tokenizer_object is not None
            }

            metadata_path = model_dir / "metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            # Update index
            self.disk_index[model_id] = {
                "path": str(model_dir),
                "saved_at": datetime.now().isoformat(),
                "size_mb": entry.memory_size / (1024 * 1024)
            }
            self._save_disk_index()

            logger.info(f"Saved model to disk cache: {model_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to save model to disk: {e}")
            return False

    def _load_from_disk(self, model_id: str) -> Optional[Tuple[Any, Optional[Any]]]:
        """Load model from disk cache.

        Args:
            model_id: Model identifier

        Returns:
            Tuple of (model, tokenizer) or None
        """
        if not self.enable_disk_cache or model_id not in self.disk_index:
            return None

        try:
            model_dir = Path(self.disk_index[model_id]["path"])
            if not model_dir.exists():
                return None

            # Load metadata
            metadata_path = model_dir / "metadata.json"
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)

            # Load model
            model_path = model_dir / "model.pkl"
            model = secure_pickle_load(model_path)

            # Load tokenizer if present
            tokenizer = None
            if metadata.get("has_tokenizer"):
                tokenizer_path = model_dir / "tokenizer.pkl"
                if tokenizer_path.exists():
                    tokenizer = secure_pickle_load(tokenizer_path)

            # Move model to appropriate device if GPU autoloader is available
            if GPU_AUTOLOADER_AVAILABLE and to_device and metadata.get("device", "cpu") != "cpu":
                try:
                    model = to_device(model, metadata["device"])
                    logger.info(f"Moved model to device: {metadata['device']}")
                except Exception as e:
                    logger.warning(f"Failed to move model to GPU, keeping on CPU: {e}")

            # Add back to memory cache
            self.put(
                model_id=model_id,
                model=model,
                tokenizer=tokenizer,
                model_type=metadata["model_type"],
                config=metadata["config"],
                load_time=metadata["load_time"],
                quantization=metadata.get("quantization"),
                adapter_info=metadata.get("adapter_info")
            )

            logger.info(f"Loaded model from disk cache: {model_id}")
            return model, tokenizer

        except Exception as e:
            logger.error(f"Failed to load model from disk: {e}")
            return None

    def clear(self, clear_disk: bool = False):
        """Clear the cache.

        Args:
            clear_disk: Also clear disk cache
        """
        # Clear memory cache
        self.cache.clear()
        self.current_memory_usage = 0

        # Clean up GPU memory
        if GPU_AUTOLOADER_AVAILABLE and empty_cache:
            empty_cache()
        elif HAS_TORCH and torch.cuda.is_available():
            torch.cuda.empty_cache()
        gc.collect()

        # Clear disk cache if requested
        if clear_disk and self.enable_disk_cache:
            import shutil
            try:
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                self.disk_index = {}
                self._save_disk_index()
            except Exception as e:
                logger.error(f"Failed to clear disk cache: {e}")

        logger.info("Cleared model cache")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        hit_rate = 0.0
        total_requests = self.stats["hits"] + self.stats["misses"]
        if total_requests > 0:
            hit_rate = self.stats["hits"] / total_requests

        stats_dict = {
            "memory_cache": {
                "entries": len(self.cache),
                "memory_used_mb": self.current_memory_usage / (1024 * 1024),
                "memory_limit_mb": self.max_memory_bytes / (1024 * 1024),
                "memory_usage_percent": (self.current_memory_usage / self.max_memory_bytes) * 100
            },
            "disk_cache": {
                "enabled": self.enable_disk_cache,
                "entries": len(self.disk_index),
                "cache_dir": str(self.cache_dir)
            },
            "statistics": {
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "hit_rate": hit_rate,
                "evictions": self.stats["evictions"],
                "avg_load_time": (
                    self.stats["total_load_time"] / self.stats["misses"]
                    if self.stats["misses"] > 0 else 0
                )
            }
        }

        # Add GPU memory stats if available
        if GPU_AUTOLOADER_AVAILABLE:
            gpu_info = get_gpu_info()
            if gpu_info and memory_allocated and memory_reserved:
                stats_dict["gpu_memory"] = {
                    "allocated_mb": memory_allocated() / (1024 * 1024),
                    "reserved_mb": memory_reserved() / (1024 * 1024),
                    "gpu_info": gpu_info
                }

        return stats_dict

    def list_cached_models(self) -> List[Dict[str, Any]]:
        """List all cached models.

        Returns:
            List of model information
        """
        models = []

        # Memory cache
        for model_id, entry in self.cache.items():
            models.append({
                "model_id": model_id,
                "location": "memory",
                "model_type": entry.model_type,
                "memory_size_mb": entry.memory_size / (1024 * 1024),
                "last_accessed": entry.last_accessed.isoformat(),
                "access_count": entry.access_count,
                "device": entry.device,
                "quantization": entry.quantization
            })

        # Disk cache
        for model_id, info in self.disk_index.items():
            if model_id not in self.cache:
                models.append({
                    "model_id": model_id,
                    "location": "disk",
                    "size_mb": info.get("size_mb", 0),
                    "saved_at": info.get("saved_at", "")
                })

        return models

    def preload_models(self, model_ids: List[str], load_functions: Dict[str, callable]):
        """Preload multiple models into cache.

        Args:
            model_ids: List of model IDs to preload
            load_functions: Dictionary of model_id -> load_function
        """
        for model_id in model_ids:
            if model_id in self.cache:
                continue

            if model_id in load_functions:
                logger.info(f"Preloading model: {model_id}")
                self.get(model_id, load_functions[model_id])

    def set_memory_limit(self, max_memory_gb: float):
        """Update memory limit.

        Args:
            max_memory_gb: New memory limit in GB
        """
        self.max_memory_bytes = int(max_memory_gb * 1024 * 1024 * 1024)

        # Evict models if over new limit
        while self.current_memory_usage > self.max_memory_bytes and len(self.cache) > 0:
            self._evict_lru()


# Global instance
_CACHE_MANAGER = None


def get_cache_manager(max_memory_gb: float = 8.0) -> ModelCacheManager:
    """Get the global model cache manager."""
    global _CACHE_MANAGER
    if _CACHE_MANAGER is None:
        _CACHE_MANAGER = ModelCacheManager(max_memory_gb=max_memory_gb)
    return _CACHE_MANAGER
