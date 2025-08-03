"""
Asynchronous AI Model Background Loader for Intellicrack.

Provides non-blocking model loading with progress tracking, priority queuing,
and memory-efficient strategies for smooth user experience.

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

import asyncio
import gc
import hashlib
import json
import logging
import os
import pickle
import psutil
import queue
import shutil
import sys
import threading
import time
import weakref
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set, Tuple, Union

from ..utils.logger import get_logger
from ..utils.structured_logging import get_structured_logger
from ..core.logging.audit_logger import get_audit_logger

if TYPE_CHECKING:
    from .llm_backends import LLMBackend, LLMConfig

logger = get_logger(__name__)
structured_logger = get_structured_logger(__name__)
audit_logger = get_audit_logger()


class LoadingStrategy(Enum):
    """Model loading strategies."""
    LAZY = "lazy"
    EAGER = "eager"
    STAGED = "staged"
    CACHED = "cached"
    DISTRIBUTED = "distributed"


class LoadingPriority(Enum):
    """Loading priority levels."""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4


class LoadingState(Enum):
    """Loading operation states."""
    PENDING = "pending"
    QUEUED = "queued"
    INITIALIZING = "initializing"
    DOWNLOADING = "downloading"
    LOADING = "loading"
    LOADED = "loaded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    WARMING = "warming"
    COMPLETED = "completed"


class ProgressCallback:
    """Base class for progress callbacks."""
    
    def on_progress(self, progress: 'LoadingProgress'):
        """Called when progress is updated."""
        logger = get_logger(__name__)
        logger.info(f"Loading progress for {progress.model_id}: {progress.percentage:.1%} - {progress.details}")
    
    def on_completed(self, model_id: str, success: bool, error: Optional[str] = None):
        """Called when loading is completed."""
        logger = get_logger(__name__)
        if success:
            logger.info(f"Successfully loaded model: {model_id}")
        else:
            logger.error(f"Failed to load model {model_id}: {error}")


@dataclass
class LoadingProgress:
    """Track loading progress for a model."""
    model_id: str
    model_name: str = ""
    total_size: int = 0
    loaded_size: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    eta_seconds: float = 0.0
    state: LoadingState = LoadingState.QUEUED
    progress: float = 0.0
    message: str = ""
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    @property
    def progress_percent(self) -> float:
        """Calculate progress percentage."""
        if self.total_size == 0:
            return self.progress * 100
        return min(100.0, (self.loaded_size / self.total_size) * 100)
    
    @property
    def elapsed_seconds(self) -> float:
        """Get elapsed seconds since start."""
        return (datetime.now() - self.start_time).total_seconds()
    
    def update_eta(self):
        """Update ETA based on current progress."""
        if self.loaded_size > 0 and self.elapsed_seconds > 0:
            rate = self.loaded_size / self.elapsed_seconds
            remaining = self.total_size - self.loaded_size
            self.eta_seconds = remaining / rate if rate > 0 else 0


@dataclass
class LoadingRequest:
    """Model loading request."""
    model_id: str
    backend_class: type = None
    config: 'LLMConfig' = None
    priority: LoadingPriority = LoadingPriority.NORMAL
    strategy: LoadingStrategy = LoadingStrategy.LAZY
    callback: Optional[ProgressCallback] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3
    timeout_seconds: float = 300.0
    
    def __lt__(self, other):
        """Compare by priority for queue ordering."""
        return self.priority.value < other.priority.value


class ModelCache:
    """Smart model caching system."""
    
    def __init__(self, cache_dir: Optional[Path] = None, max_size_gb: float = 10.0):
        """Initialize model cache.
        
        Args:
            cache_dir: Directory for cache storage
            max_size_gb: Maximum cache size in GB
        """
        self.cache_dir = cache_dir or Path.home() / ".intellicrack" / "model_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_size_bytes = int(max_size_gb * 1024 * 1024 * 1024)
        self.cache_index = self._load_index()
        self.lock = threading.RLock()
        
    def _load_index(self) -> Dict[str, Dict[str, Any]]:
        """Load cache index from disk."""
        index_path = self.cache_dir / "cache_index.json"
        if index_path.exists():
            try:
                with open(index_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load cache index: {e}")
        return {}
    
    def _save_index(self):
        """Save cache index to disk."""
        index_path = self.cache_dir / "cache_index.json"
        try:
            with open(index_path, 'w') as f:
                json.dump(self.cache_index, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache index: {e}")
    
    def _get_cache_path(self, model_id: str, component: str = "main") -> Path:
        """Get cache file path for model component."""
        safe_id = hashlib.sha256(model_id.encode()).hexdigest()[:16]
        return self.cache_dir / f"{safe_id}_{component}.cache"
    
    def has_cached(self, model_id: str, component: str = "main") -> bool:
        """Check if model component is cached."""
        with self.lock:
            cache_key = f"{model_id}:{component}"
            if cache_key in self.cache_index:
                cache_path = self._get_cache_path(model_id, component)
                return cache_path.exists()
            return False
    
    def get_cached(self, model_id: str, component: str = "main") -> Optional[Any]:
        """Retrieve cached model component."""
        with self.lock:
            cache_path = self._get_cache_path(model_id, component)
            if cache_path.exists():
                try:
                    with open(cache_path, 'rb') as f:
                        data = pickle.load(f)
                    # Update access time
                    cache_key = f"{model_id}:{component}"
                    self.cache_index[cache_key]["last_access"] = datetime.now().isoformat()
                    self._save_index()
                    return data
                except Exception as e:
                    logger.error(f"Failed to load cached model {model_id}: {e}")
        return None
    
    def cache_model(self, model_id: str, data: Any, component: str = "main", 
                   metadata: Optional[Dict[str, Any]] = None):
        """Cache model component."""
        with self.lock:
            cache_path = self._get_cache_path(model_id, component)
            try:
                # Serialize model data
                with open(cache_path, 'wb') as f:
                    pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
                
                # Update index
                cache_key = f"{model_id}:{component}"
                self.cache_index[cache_key] = {
                    "model_id": model_id,
                    "component": component,
                    "size": cache_path.stat().st_size,
                    "created": datetime.now().isoformat(),
                    "last_access": datetime.now().isoformat(),
                    "metadata": metadata or {}
                }
                self._save_index()
                
                # Cleanup if over size limit
                self._cleanup_cache()
                
            except Exception as e:
                logger.error(f"Failed to cache model {model_id}: {e}")
                if cache_path.exists():
                    cache_path.unlink()
    
    def _cleanup_cache(self):
        """Remove old cache entries if over size limit."""
        total_size = sum(entry["size"] for entry in self.cache_index.values())
        
        if total_size > self.max_size_bytes:
            # Sort by last access time
            sorted_entries = sorted(
                self.cache_index.items(),
                key=lambda x: x[1]["last_access"]
            )
            
            # Remove oldest entries until under limit
            for cache_key, entry in sorted_entries:
                if total_size <= self.max_size_bytes:
                    break
                    
                model_id = entry["model_id"]
                component = entry["component"]
                cache_path = self._get_cache_path(model_id, component)
                
                if cache_path.exists():
                    cache_path.unlink()
                    total_size -= entry["size"]
                    del self.cache_index[cache_key]
            
            self._save_index()


class LoadingProfiler:
    """Profile and predict loading times."""
    
    def __init__(self):
        """Initialize loading profiler."""
        self.history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.lock = threading.Lock()
        
    def record_loading(self, model_id: str, size_bytes: int, duration_seconds: float,
                      strategy: LoadingStrategy, success: bool):
        """Record loading operation."""
        with self.lock:
            self.history[model_id].append({
                "timestamp": datetime.now().isoformat(),
                "size_bytes": size_bytes,
                "duration_seconds": duration_seconds,
                "strategy": strategy.value,
                "success": success,
                "rate_mbps": (size_bytes / (1024 * 1024)) / duration_seconds if duration_seconds > 0 else 0
            })
            
            # Keep only last 100 records per model
            if len(self.history[model_id]) > 100:
                self.history[model_id] = self.history[model_id][-100:]
    
    def predict_loading_time(self, model_id: str, size_bytes: int) -> float:
        """Predict loading time based on history."""
        with self.lock:
            if model_id in self.history:
                # Use model-specific history
                records = self.history[model_id]
            else:
                # Use all history
                records = [r for records in self.history.values() for r in records]
            
            if not records:
                # Default estimate: 50 MB/s
                return size_bytes / (50 * 1024 * 1024)
            
            # Calculate average loading rate
            successful_records = [r for r in records if r["success"]]
            if successful_records:
                avg_rate = sum(r["rate_mbps"] for r in successful_records) / len(successful_records)
                return (size_bytes / (1024 * 1024)) / avg_rate if avg_rate > 0 else 60.0
            
            return 60.0  # Default 1 minute


class ResourceMonitor:
    """Monitor system resources for loading decisions."""
    
    def __init__(self, loader: 'BackgroundLoader'):
        """Initialize resource monitor."""
        self.loader = loader
        self.current_memory_usage = 0
        self.current_gpu_usage = 0
        self.lock = threading.Lock()
        
    def update(self):
        """Update resource usage metrics."""
        try:
            # Get system memory
            memory = psutil.virtual_memory()
            self.current_memory_usage = memory.used
            
            # Get GPU memory if available
            if hasattr(self.loader.model_manager, 'get_gpu_memory_usage'):
                self.current_gpu_usage = self.loader.model_manager.get_gpu_memory_usage()
            
        except Exception as e:
            logger.error(f"Failed to update resource metrics: {e}")
    
    def can_load_model(self, model_id: str) -> bool:
        """Check if resources are available to load a model."""
        try:
            # Get model requirements
            if hasattr(self.loader.model_manager, 'get_model_requirements'):
                requirements = self.loader.model_manager.get_model_requirements(model_id)
                required_memory = requirements.get('memory_bytes', 0)
                
                # Check memory availability
                memory = psutil.virtual_memory()
                available_memory = memory.available
                
                # Leave at least 1GB free
                if available_memory - required_memory < 1024 * 1024 * 1024:
                    return False
                
                # Check against loader limits
                if (self.current_memory_usage + required_memory > 
                    self.loader.max_memory_bytes):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to check resource availability: {e}")
            return True  # Allow loading on error


class UsagePatternTracker:
    """Track model usage patterns for predictive loading."""
    
    def __init__(self):
        """Initialize usage pattern tracker."""
        self.usage_history: Dict[str, List[datetime]] = defaultdict(list)
        self.loading_sequences: List[List[str]] = []
        self.lock = threading.Lock()
        
    def record_loading(self, model_id: str, success: bool):
        """Record model loading event."""
        if not success:
            return
            
        with self.lock:
            # Record timestamp
            self.usage_history[model_id].append(datetime.now())
            
            # Keep only last 100 uses
            if len(self.usage_history[model_id]) > 100:
                self.usage_history[model_id] = self.usage_history[model_id][-100:]
            
            # Update loading sequences
            if self.loading_sequences:
                last_sequence = self.loading_sequences[-1]
                if len(last_sequence) < 10:  # Max sequence length
                    last_sequence.append(model_id)
                else:
                    self.loading_sequences.append([model_id])
            else:
                self.loading_sequences.append([model_id])
            
            # Keep only last 50 sequences
            if len(self.loading_sequences) > 50:
                self.loading_sequences = self.loading_sequences[-50:]
    
    def get_usage_score(self, model_id: str) -> float:
        """Get usage score for a model (0-1)."""
        with self.lock:
            if model_id not in self.usage_history:
                return 0.0
            
            uses = self.usage_history[model_id]
            if not uses:
                return 0.0
            
            # Recent usage weight
            now = datetime.now()
            recent_uses = sum(1 for use in uses 
                            if (now - use).total_seconds() < 3600)  # Last hour
            
            # Frequency score
            frequency_score = min(1.0, recent_uses / 10)
            
            # Consistency score (regular usage pattern)
            if len(uses) > 5:
                intervals = [(uses[i] - uses[i-1]).total_seconds() 
                           for i in range(1, len(uses))]
                avg_interval = sum(intervals) / len(intervals)
                std_interval = (sum((x - avg_interval) ** 2 for x in intervals) 
                              / len(intervals)) ** 0.5
                consistency_score = 1.0 / (1.0 + std_interval / avg_interval)
            else:
                consistency_score = 0.5
            
            return 0.7 * frequency_score + 0.3 * consistency_score
    
    def predict_next_models(self, count: int = 5) -> List[Tuple[str, float]]:
        """Predict next likely models to be used."""
        with self.lock:
            predictions = {}
            
            # Analyze sequences
            for sequence in self.loading_sequences[-10:]:  # Last 10 sequences
                for i in range(len(sequence) - 1):
                    current = sequence[i]
                    next_model = sequence[i + 1]
                    
                    if current in self.usage_history:
                        # Check if current model was recently used
                        recent_use = any((datetime.now() - use).total_seconds() < 300
                                       for use in self.usage_history[current][-5:])
                        if recent_use:
                            predictions[next_model] = predictions.get(next_model, 0) + 1
            
            # Normalize to probabilities
            total = sum(predictions.values())
            if total > 0:
                predictions = {k: v/total for k, v in predictions.items()}
            
            # Sort by probability
            sorted_predictions = sorted(predictions.items(), 
                                      key=lambda x: x[1], 
                                      reverse=True)
            
            return sorted_predictions[:count]


class ConsoleProgressCallback(ProgressCallback):
    """Console-based progress callback for debugging."""

    def on_progress(self, progress: LoadingProgress):
        """Print progress to console."""
        print(f"[{progress.model_id}] {progress.state.value}: "
              f"{progress.progress:.1%} - {progress.message}")

    def on_completed(self, model_id: str, success: bool, error: Optional[str] = None):
        """Print completion status."""
        status = "SUCCESS" if success else f"FAILED: {error}"
        print(f"[{model_id}] Loading completed: {status}")


class QueuedProgressCallback(ProgressCallback):
    """Queue-based progress callback for GUI integration."""

    def __init__(self):
        """Initialize the queue-based progress callback.

        Sets up queues for progress updates and completion notifications
        for thread-safe communication with GUI components.
        """
        self.progress_queue = queue.Queue()
        self.completion_queue = queue.Queue()
        self.logger = logging.getLogger(__name__ + ".QueuedProgressCallback")

    def on_progress(self, progress: LoadingProgress):
        """Add progress to queue."""
        self.progress_queue.put(progress)

    def on_completed(self, model_id: str, success: bool, error: Optional[str] = None):
        """Add completion to queue."""
        self.completion_queue.put((model_id, success, error))

    def get_progress_updates(self) -> List[LoadingProgress]:
        """Get all pending progress updates."""
        updates = []
        try:
            while True:
                updates.append(self.progress_queue.get_nowait())
        except queue.Empty:
            pass
        return updates

    def get_completion_updates(self) -> List[tuple]:
        """Get all pending completion updates."""
        updates = []
        try:
            while True:
                updates.append(self.completion_queue.get_nowait())
        except queue.Empty:
            pass
        return updates


class BackgroundLoader:
    """Asynchronous background model loader."""
    
    def __init__(self, model_manager: Any, max_workers: int = 4,
                 max_memory_gb: float = 8.0, cache_enabled: bool = True):
        """Initialize background loader.
        
        Args:
            model_manager: Model manager instance
            max_workers: Maximum concurrent loading workers
            max_memory_gb: Maximum memory usage in GB
            cache_enabled: Enable model caching
        """
        self.model_manager = model_manager
        self.max_workers = max_workers
        self.max_memory_bytes = int(max_memory_gb * 1024 * 1024 * 1024)
        
        # Loading queue with priority
        self.loading_queue = queue.PriorityQueue()
        self.active_loads: Dict[str, LoadingProgress] = {}
        self.completed_loads: Dict[str, LoadingProgress] = {}
        
        # Thread pool for loading operations
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.process_executor = ProcessPoolExecutor(max_workers=2)
        
        # Caching and profiling
        self.cache = ModelCache() if cache_enabled else None
        self.profiler = LoadingProfiler()
        
        # Resource monitoring
        self.resource_monitor = ResourceMonitor(self)
        
        # Loading patterns for predictive preloading
        self.usage_patterns = UsagePatternTracker()
        
        # State management
        self.running = True
        self.lock = threading.RLock()
        self.event_callbacks: Dict[str, List[Callable]] = defaultdict(list)
        
        # Start worker threads
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        
        # Start resource monitor
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        structured_logger.info("background_loader_initialized", 
                             max_workers=max_workers,
                             max_memory_gb=max_memory_gb,
                             cache_enabled=cache_enabled)
    
    def load_model(self, model_id: str, priority: LoadingPriority = LoadingPriority.NORMAL,
                  strategy: LoadingStrategy = LoadingStrategy.LAZY,
                  callback: Optional[ProgressCallback] = None,
                  metadata: Optional[Dict[str, Any]] = None,
                  backend_class: Optional[type] = None,
                  config: Optional['LLMConfig'] = None) -> LoadingProgress:
        """Queue model for loading.
        
        Args:
            model_id: Model identifier
            priority: Loading priority
            strategy: Loading strategy
            callback: Completion callback
            metadata: Additional metadata
            backend_class: Backend class for model
            config: Model configuration
            
        Returns:
            LoadingProgress object for tracking
        """
        with self.lock:
            # Check if already loading or loaded
            if model_id in self.active_loads:
                progress = self.active_loads[model_id]
                if callback:
                    self._add_callback(model_id, callback)
                return progress
            
            if model_id in self.completed_loads:
                progress = self.completed_loads[model_id]
                if progress.state == LoadingState.LOADED:
                    if callback:
                        callback.on_completed(True, model_id, None)
                    return progress
            
            # Create loading request
            request = LoadingRequest(
                model_id=model_id,
                backend_class=backend_class,
                config=config,
                priority=priority,
                strategy=strategy,
                callback=callback,
                metadata=metadata or {}
            )
            
            # Create progress tracker
            progress = LoadingProgress(
                model_id=model_id,
                model_name=config.model_name if config else model_id
            )
            self.active_loads[model_id] = progress
            
            # Add to queue
            self.loading_queue.put(request)
            
            structured_logger.info("model_loading_queued",
                                 model_id=model_id,
                                 priority=priority.value,
                                 strategy=strategy.value)
            
            return progress
    
    def load_models_batch(self, model_configs: List[Dict[str, Any]], 
                         priority: LoadingPriority = LoadingPriority.NORMAL,
                         parallel: bool = True) -> Dict[str, LoadingProgress]:
        """Load multiple models as a batch.
        
        Args:
            model_configs: List of model configurations
            priority: Loading priority for all models
            parallel: Load models in parallel
            
        Returns:
            Dictionary of model_id to LoadingProgress
        """
        progress_map = {}
        
        for i, config in enumerate(model_configs):
            # Adjust priority for sequential loading
            adjusted_priority = priority if parallel else LoadingPriority(
                min(priority.value + i, LoadingPriority.BACKGROUND.value)
            )
            
            progress = self.load_model(
                model_id=config['model_id'],
                priority=adjusted_priority,
                strategy=LoadingStrategy.EAGER if parallel else LoadingStrategy.STAGED,
                backend_class=config.get('backend_class'),
                config=config.get('config')
            )
            progress_map[config['model_id']] = progress
        
        return progress_map
    
    def preload_models(self, model_ids: List[str]):
        """Preload models based on usage patterns."""
        for model_id in model_ids:
            self.load_model(
                model_id=model_id,
                priority=LoadingPriority.BACKGROUND,
                strategy=LoadingStrategy.EAGER
            )
    
    def cancel_loading(self, model_id: str) -> bool:
        """Cancel a loading operation.
        
        Args:
            model_id: Model to cancel loading for
            
        Returns:
            True if cancelled, False if not found or already loaded
        """
        with self.lock:
            if model_id in self.active_loads:
                progress = self.active_loads[model_id]
                if progress.state in [LoadingState.QUEUED, LoadingState.LOADING]:
                    progress.state = LoadingState.CANCELLED
                    progress.error = "Cancelled by user"
                    
                    # Move to completed
                    self.completed_loads[model_id] = progress
                    del self.active_loads[model_id]
                    
                    # Notify callbacks
                    self._notify_callbacks(model_id, False, "Cancelled")
                    
                    structured_logger.info("model_loading_cancelled", model_id=model_id)
                    return True
        
        return False
    
    def pause_loading(self, model_id: str) -> bool:
        """Pause a loading operation."""
        with self.lock:
            if model_id in self.active_loads:
                progress = self.active_loads[model_id]
                if progress.state == LoadingState.LOADING:
                    progress.state = LoadingState.PAUSED
                    return True
        return False
    
    def resume_loading(self, model_id: str) -> bool:
        """Resume a paused loading operation."""
        with self.lock:
            if model_id in self.active_loads:
                progress = self.active_loads[model_id]
                if progress.state == LoadingState.PAUSED:
                    progress.state = LoadingState.LOADING
                    return True
        return False
    
    def get_progress(self, model_id: str) -> Optional[LoadingProgress]:
        """Get loading progress for a model."""
        with self.lock:
            if model_id in self.active_loads:
                return self.active_loads[model_id]
            if model_id in self.completed_loads:
                return self.completed_loads[model_id]
        return None
    
    def get_all_progress(self) -> Dict[str, LoadingProgress]:
        """Get progress for all models."""
        with self.lock:
            all_progress = {}
            all_progress.update(self.active_loads)
            all_progress.update(self.completed_loads)
            return all_progress
    
    def warm_up_model(self, model_id: str, sample_data: Optional[Any] = None):
        """Warm up a loaded model."""
        def warm_up_task():
            try:
                progress = self.get_progress(model_id)
                if progress and progress.state == LoadingState.LOADED:
                    progress.state = LoadingState.WARMING
                    
                    # Perform warm-up inference
                    if hasattr(self.model_manager, 'warm_up_model'):
                        self.model_manager.warm_up_model(model_id, sample_data)
                    
                    progress.state = LoadingState.LOADED
                    structured_logger.info("model_warmed_up", model_id=model_id)
                    
            except Exception as e:
                logger.error(f"Failed to warm up model {model_id}: {e}")
        
        self.executor.submit(warm_up_task)
    
    def optimize_loading_queue(self):
        """Optimize loading queue based on patterns and resources."""
        with self.lock:
            # Get current queue items
            items = []
            while not self.loading_queue.empty():
                try:
                    items.append(self.loading_queue.get_nowait())
                except queue.Empty:
                    break
            
            # Re-prioritize based on usage patterns
            for item in items:
                # Boost priority for frequently used models
                usage_score = self.usage_patterns.get_usage_score(item.model_id)
                if usage_score > 0.8:
                    item.priority = LoadingPriority(
                        max(LoadingPriority.HIGH.value, item.priority.value - 1)
                    )
            
            # Re-add to queue
            for item in sorted(items):
                self.loading_queue.put(item)
    
    def _worker_loop(self):
        """Main worker loop for processing loading requests."""
        while self.running:
            try:
                # Get next loading request
                request = self.loading_queue.get(timeout=1.0)
                
                # Check resource availability
                if not self.resource_monitor.can_load_model(request.model_id):
                    # Re-queue with slight delay
                    time.sleep(0.5)
                    self.loading_queue.put(request)
                    continue
                
                # Execute loading
                self._execute_loading(request)
                
            except queue.Empty:
                # No requests, check for predictive preloading
                self._check_predictive_preload()
            except Exception as e:
                logger.error(f"Error in worker loop: {e}")
    
    def _execute_loading(self, request: LoadingRequest):
        """Execute a loading request."""
        model_id = request.model_id
        progress = self.active_loads.get(model_id)
        
        if not progress:
            return
        
        # Update state
        progress.state = LoadingState.LOADING
        start_time = time.time()
        
        try:
            # Check cache first
            if self.cache and request.strategy != LoadingStrategy.STAGED:
                cached_model = self.cache.get_cached(model_id)
                if cached_model:
                    # Simulate loading for UI feedback
                    progress.total_size = 1000
                    progress.loaded_size = 1000
                    
                    # Register with model manager
                    if hasattr(self.model_manager, 'register_cached_model'):
                        self.model_manager.register_cached_model(model_id, cached_model)
                    
                    self._loading_completed(request, progress, True, time.time() - start_time)
                    return
            
            # Execute strategy-specific loading
            if request.strategy == LoadingStrategy.LAZY:
                self._load_lazy(request, progress)
            elif request.strategy == LoadingStrategy.EAGER:
                self._load_eager(request, progress)
            elif request.strategy == LoadingStrategy.STAGED:
                self._load_staged(request, progress)
            elif request.strategy == LoadingStrategy.DISTRIBUTED:
                self._load_distributed(request, progress)
            else:
                # Default loading
                self._load_standard(request, progress)
            
        except Exception as e:
            logger.error(f"Failed to load model {model_id}: {e}")
            self._loading_failed(request, progress, str(e))
    
    def _load_standard(self, request: LoadingRequest, progress: LoadingProgress):
        """Standard model loading."""
        model_id = request.model_id
        
        try:
            # Get model info for size estimation
            if hasattr(self.model_manager, 'get_model_info'):
                model_info = self.model_manager.get_model_info(model_id)
                progress.total_size = model_info.get('size_bytes', 0)
            
            # Predict loading time
            predicted_time = self.profiler.predict_loading_time(
                model_id, progress.total_size
            )
            progress.eta_seconds = predicted_time
            
            # Update progress
            progress.state = LoadingState.INITIALIZING
            progress.message = "Initializing model loading..."
            progress.progress = 0.1
            if request.callback:
                request.callback.on_progress(progress)
            
            # Load model with progress callback
            def progress_callback(loaded_bytes: int):
                progress.loaded_size = loaded_bytes
                progress.update_eta()
                progress.progress = min(0.9, 0.1 + (loaded_bytes / progress.total_size) * 0.8)
                if request.callback:
                    request.callback.on_progress(progress)
            
            # Perform loading
            start_time = time.time()
            
            if request.backend_class and request.config:
                # Load with provided backend
                backend = request.backend_class(request.config)
                success = backend.initialize()
                if success:
                    model = backend
                else:
                    raise RuntimeError("Backend initialization failed")
            elif hasattr(self.model_manager, 'load_model_with_progress'):
                model = self.model_manager.load_model_with_progress(
                    model_id, progress_callback
                )
            else:
                model = self.model_manager.load_model(model_id)
                progress.loaded_size = progress.total_size
            
            duration = time.time() - start_time
            
            # Cache if enabled
            if self.cache and model:
                self.cache.cache_model(model_id, model)
            
            # Record profiling data
            self.profiler.record_loading(
                model_id, progress.total_size, duration,
                request.strategy, True
            )
            
            self._loading_completed(request, progress, True, duration)
            
        except Exception as e:
            self._loading_failed(request, progress, str(e))
    
    def _load_lazy(self, request: LoadingRequest, progress: LoadingProgress):
        """Lazy loading - load only essential components."""
        model_id = request.model_id
        
        try:
            # Load metadata only
            if hasattr(self.model_manager, 'load_model_metadata'):
                metadata = self.model_manager.load_model_metadata(model_id)
                progress.metadata['lazy_metadata'] = metadata
                
                # Create lazy loader proxy
                if hasattr(self.model_manager, 'create_lazy_model'):
                    model = self.model_manager.create_lazy_model(model_id, metadata)
                    self._loading_completed(request, progress, True, 0)
                else:
                    # Fall back to standard loading
                    self._load_standard(request, progress)
            else:
                self._load_standard(request, progress)
                
        except Exception as e:
            self._loading_failed(request, progress, str(e))
    
    def _load_eager(self, request: LoadingRequest, progress: LoadingProgress):
        """Eager loading - load and prepare everything."""
        # First do standard loading
        self._load_standard(request, progress)
        
        # Then warm up if successful
        if progress.state == LoadingState.LOADED:
            self.warm_up_model(request.model_id)
    
    def _load_staged(self, request: LoadingRequest, progress: LoadingProgress):
        """Staged loading - load model in stages."""
        model_id = request.model_id
        
        try:
            stages = ['weights', 'config', 'tokenizer', 'optimizer']
            total_stages = len(stages)
            
            for i, stage in enumerate(stages):
                if progress.state == LoadingState.CANCELLED:
                    break
                
                # Check if paused
                while progress.state == LoadingState.PAUSED:
                    time.sleep(0.1)
                
                # Load stage
                if hasattr(self.model_manager, 'load_model_stage'):
                    self.model_manager.load_model_stage(model_id, stage)
                
                # Update progress
                progress.loaded_size = int((i + 1) / total_stages * progress.total_size)
                progress.update_eta()
                
                # Cache stage if available
                if self.cache:
                    stage_data = getattr(self.model_manager, f'get_{stage}', None)
                    if stage_data:
                        self.cache.cache_model(model_id, stage_data(model_id), stage)
            
            if progress.state != LoadingState.CANCELLED:
                self._loading_completed(request, progress, True, 0)
            
        except Exception as e:
            self._loading_failed(request, progress, str(e))
    
    def _load_distributed(self, request: LoadingRequest, progress: LoadingProgress):
        """Distributed loading across multiple processes."""
        model_id = request.model_id
        
        try:
            # Split loading across processes
            if hasattr(self.model_manager, 'get_model_shards'):
                shards = self.model_manager.get_model_shards(model_id)
                
                # Load shards in parallel
                futures = []
                for shard in shards:
                    future = self.process_executor.submit(
                        self._load_shard, model_id, shard
                    )
                    futures.append(future)
                
                # Wait for completion
                loaded_shards = []
                for future in futures:
                    try:
                        shard_data = future.result(timeout=request.timeout_seconds)
                        loaded_shards.append(shard_data)
                    except Exception as e:
                        logger.error(f"Failed to load shard: {e}")
                
                # Combine shards
                if hasattr(self.model_manager, 'combine_model_shards'):
                    model = self.model_manager.combine_model_shards(model_id, loaded_shards)
                    self._loading_completed(request, progress, True, 0)
                else:
                    self._load_standard(request, progress)
            else:
                self._load_standard(request, progress)
                
        except Exception as e:
            self._loading_failed(request, progress, str(e))
    
    def _load_shard(self, model_id: str, shard_info: Dict[str, Any]) -> Any:
        """Load a model shard in a separate process."""
        # This runs in a separate process
        if hasattr(self.model_manager, 'load_model_shard'):
            return self.model_manager.load_model_shard(model_id, shard_info)
        return None
    
    def _loading_completed(self, request: LoadingRequest, progress: LoadingProgress,
                          success: bool, duration: float):
        """Handle loading completion."""
        with self.lock:
            progress.state = LoadingState.COMPLETED if success else LoadingState.FAILED
            progress.progress = 1.0 if success else progress.progress
            progress.message = "Model loaded successfully" if success else "Loading failed"
            
            # Move to completed
            self.completed_loads[request.model_id] = progress
            if request.model_id in self.active_loads:
                del self.active_loads[request.model_id]
            
            # Update usage patterns
            self.usage_patterns.record_loading(request.model_id, success)
            
            # Notify callbacks
            self._notify_callbacks(request.model_id, success, None)
            
            structured_logger.info("model_loading_completed",
                                 model_id=request.model_id,
                                 success=success,
                                 duration_seconds=duration,
                                 strategy=request.strategy.value)
    
    def _loading_failed(self, request: LoadingRequest, progress: LoadingProgress,
                       error: str):
        """Handle loading failure."""
        progress.state = LoadingState.FAILED
        progress.error = error
        
        # Check retry
        if request.retry_count < request.max_retries:
            request.retry_count += 1
            request.priority = LoadingPriority(
                max(LoadingPriority.HIGH.value, request.priority.value - 1)
            )
            self.loading_queue.put(request)
            
            structured_logger.warning("model_loading_retry",
                                    model_id=request.model_id,
                                    retry_count=request.retry_count,
                                    error=error)
        else:
            self._loading_completed(request, progress, False, 0)
    
    def _check_predictive_preload(self):
        """Check if any models should be preloaded."""
        predictions = self.usage_patterns.predict_next_models(5)
        
        for model_id, probability in predictions:
            if probability > 0.7:  # High probability threshold
                # Check if not already loaded or loading
                with self.lock:
                    if (model_id not in self.active_loads and 
                        model_id not in self.completed_loads):
                        self.load_model(
                            model_id=model_id,
                            priority=LoadingPriority.BACKGROUND,
                            strategy=LoadingStrategy.LAZY
                        )
    
    def _monitor_loop(self):
        """Monitor resource usage and optimize loading."""
        while self.running:
            try:
                # Monitor every 5 seconds
                time.sleep(5)
                
                # Update resource usage
                self.resource_monitor.update()
                
                # Optimize queue if needed
                if self.loading_queue.qsize() > 5:
                    self.optimize_loading_queue()
                
                # Cleanup completed loads older than 1 hour
                self._cleanup_old_completed()
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
    
    def _cleanup_old_completed(self):
        """Remove old completed loading records."""
        with self.lock:
            cutoff_time = datetime.now() - timedelta(hours=1)
            
            to_remove = []
            for model_id, progress in self.completed_loads.items():
                if progress.start_time < cutoff_time:
                    to_remove.append(model_id)
            
            for model_id in to_remove:
                del self.completed_loads[model_id]
    
    def _add_callback(self, model_id: str, callback: Callable):
        """Add a callback for model loading completion."""
        if isinstance(callback, ProgressCallback):
            self.event_callbacks[model_id].append(callback)
    
    def _notify_callbacks(self, model_id: str, success: bool, error: Optional[str]):
        """Notify all callbacks for a model."""
        callbacks = self.event_callbacks.pop(model_id, [])
        
        for callback in callbacks:
            try:
                if isinstance(callback, ProgressCallback):
                    callback.on_completed(model_id, success, error)
                elif callable(callback):
                    callback(success, model_id, error)
            except Exception as e:
                logger.error(f"Error in loading callback: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get loading statistics."""
        with self.lock:
            stats = {
                "pending": self.loading_queue.qsize(),
                "active": len(self.active_loads),
                "completed": len(self.completed_loads),
                "max_workers": self.max_workers,
                "cache_enabled": self.cache is not None,
                "resource_usage": {
                    "memory_used": self.resource_monitor.current_memory_usage,
                    "memory_limit": self.max_memory_bytes,
                    "gpu_used": self.resource_monitor.current_gpu_usage
                }
            }
            
            # Calculate success rate
            completed_tasks = list(self.completed_loads.values())
            if completed_tasks:
                successful = sum(
                    1 for task in completed_tasks if task.state == LoadingState.COMPLETED
                )
                stats["success_rate"] = successful / len(completed_tasks)
            else:
                stats["success_rate"] = 0.0
            
            return stats
    
    def shutdown(self):
        """Shutdown the background loader."""
        self.running = False
        
        # Cancel all active loads
        with self.lock:
            for model_id in list(self.active_loads.keys()):
                self.cancel_loading(model_id)
        
        # Shutdown executors
        self.executor.shutdown(wait=True)
        self.process_executor.shutdown(wait=True)
        
        structured_logger.info("background_loader_shutdown")


# Module initialization
_background_loader_instance = None


def get_background_loader(model_manager: Any = None, **kwargs) -> BackgroundLoader:
    """Get or create the global background loader instance.
    
    Args:
        model_manager: Model manager instance (required for first call)
        **kwargs: Additional arguments for BackgroundLoader
        
    Returns:
        BackgroundLoader instance
    """
    global _background_loader_instance
    
    if _background_loader_instance is None:
        if model_manager is None:
            raise ValueError("Model manager required for first initialization")
        _background_loader_instance = BackgroundLoader(model_manager, **kwargs)
    
    return _background_loader_instance


class IntegratedBackgroundLoader:
    """
    Integration layer between background loader and model manager.

    Provides seamless integration with lazy loading and model management.
    """

    def __init__(self, model_manager: Any, max_concurrent_loads: int = 2,
                 max_memory_gb: float = 8.0, cache_enabled: bool = True):
        """Initialize the integrated background loader.

        Args:
            model_manager: Model manager instance for model registration
            max_concurrent_loads: Maximum number of concurrent model loads
            max_memory_gb: Maximum memory usage in GB
            cache_enabled: Enable model caching
        """
        self.model_manager = model_manager
        self.background_loader = BackgroundLoader(
            model_manager, max_concurrent_loads, max_memory_gb, cache_enabled
        )
        self.progress_callbacks: List[ProgressCallback] = []

    def add_progress_callback(self, callback: ProgressCallback):
        """Add a progress callback."""
        self.progress_callbacks.append(callback)

    def remove_progress_callback(self, callback: ProgressCallback):
        """Remove a progress callback."""
        if callback in self.progress_callbacks:
            self.progress_callbacks.remove(callback)

    def load_model_in_background(self,
                                 model_id: str,
                                 backend_class: type = None,
                                 config: 'LLMConfig' = None,
                                 priority: LoadingPriority = LoadingPriority.NORMAL,
                                 strategy: LoadingStrategy = LoadingStrategy.LAZY) -> LoadingProgress:
        """Load a model in the background with integrated callbacks."""

        # Create a callback that notifies all registered callbacks
        class MultiCallback(ProgressCallback):
            def __init__(self, callbacks):
                """Initialize multi-callback handler with list of callbacks."""
                self.callbacks = callbacks

            def on_progress(self, progress):
                for callback in self.callbacks:
                    try:
                        callback.on_progress(progress)
                    except Exception as e:
                        logger.warning(f"Error in progress callback: {e}")

            def on_completed(self, model_id, success, error=None):
                for callback in self.callbacks:
                    try:
                        callback.on_completed(model_id, success, error)
                    except Exception as e:
                        logger.warning(f"Error in completion callback: {e}")

        multi_callback = MultiCallback(self.progress_callbacks) if self.progress_callbacks else None

        return self.background_loader.load_model(
            model_id=model_id,
            backend_class=backend_class,
            config=config,
            priority=priority,
            strategy=strategy,
            callback=multi_callback
        )

    def get_loading_progress(self, model_id: str) -> Optional[LoadingProgress]:
        """Get loading progress for a model."""
        return self.background_loader.get_progress(model_id)

    def cancel_loading(self, model_id: str) -> bool:
        """Cancel loading a model."""
        return self.background_loader.cancel_loading(model_id)

    def get_all_loading_tasks(self) -> Dict[str, LoadingProgress]:
        """Get all loading tasks."""
        return self.background_loader.get_all_progress()

    def get_statistics(self) -> Dict[str, Any]:
        """Get loading statistics."""
        return self.background_loader.get_statistics()

    def shutdown(self):
        """Shutdown the integrated loader."""
        self.background_loader.shutdown()


# Backwards compatibility classes
class LoadingTask:
    """Legacy LoadingTask wrapper for backwards compatibility."""
    
    def __init__(self, progress: LoadingProgress):
        self.progress = progress
        
    @property
    def model_id(self):
        return self.progress.model_id
        
    @property
    def state(self):
        return self.progress.state
        
    @property
    def message(self):
        return self.progress.message
        
    @property
    def error(self):
        return self.progress.error


class BackgroundModelLoader:
    """Legacy BackgroundModelLoader wrapper for backwards compatibility."""
    
    def __init__(self, max_concurrent_loads: int = 2):
        # Create a minimal model manager if needed
        from . import model_manager_module
        self.loader = BackgroundLoader(
            model_manager=model_manager_module,
            max_workers=max_concurrent_loads
        )
        
    def submit_loading_task(self, model_id: str, backend_class: type,
                           config: 'LLMConfig', priority: int = 0,
                           callback: Optional[ProgressCallback] = None):
        """Submit a loading task (legacy interface)."""
        progress = self.loader.load_model(
            model_id=model_id,
            backend_class=backend_class,
            config=config,
            priority=LoadingPriority(min(priority, 4)),
            callback=callback
        )
        return LoadingTask(progress)
        
    def get_task_status(self, model_id: str):
        """Get task status (legacy interface)."""
        progress = self.loader.get_progress(model_id)
        return LoadingTask(progress) if progress else None
        
    def cancel_task(self, model_id: str) -> bool:
        """Cancel a task (legacy interface)."""
        return self.loader.cancel_loading(model_id)
        
    def get_loading_statistics(self) -> Dict[str, Any]:
        """Get statistics (legacy interface)."""
        return self.loader.get_statistics()
        
    def shutdown(self):
        """Shutdown (legacy interface)."""
        self.loader.shutdown()


# Global integrated loader instance
_integrated_loader: Optional[IntegratedBackgroundLoader] = None


def get_integrated_background_loader(model_manager=None) -> IntegratedBackgroundLoader:
    """Get the global integrated background loader."""
    global _integrated_loader
    if _integrated_loader is None:
        if model_manager is None:
            from .model_manager_module import ModelManager
            model_manager = ModelManager()
        _integrated_loader = IntegratedBackgroundLoader(model_manager)
    return _integrated_loader


def load_model_with_progress(model_id: str,
                             backend_class: type = None,
                             config: 'LLMConfig' = None,
                             priority: int = 0,
                             callback: Optional[ProgressCallback] = None) -> LoadingProgress:
    """Convenience function to load a model with progress."""
    loader = get_integrated_background_loader()
    if callback:
        loader.add_progress_callback(callback)
    return loader.load_model_in_background(
        model_id, backend_class, config, 
        LoadingPriority(min(priority, 4))
    )


# Example usage and testing
if __name__ == "__main__":
    import os
    import sys

    # Add project root to path
    sys.path.insert(0, os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', '..')))

    # Example usage
    print("Testing Background Model Loading")
    print("=" * 40)

    # Create a console callback for testing
    console_callback = ConsoleProgressCallback()

    # Create test loader
    from .model_manager_module import ModelManager
    manager = ModelManager()
    loader = BackgroundLoader(manager)

    # Test different loading strategies
    test_models = [
        ("model-lazy", LoadingStrategy.LAZY, LoadingPriority.NORMAL),
        ("model-eager", LoadingStrategy.EAGER, LoadingPriority.HIGH),
        ("model-cached", LoadingStrategy.CACHED, LoadingPriority.LOW),
    ]

    for model_id, strategy, priority in test_models:
        progress = loader.load_model(
            model_id=model_id,
            strategy=strategy,
            priority=priority,
            callback=console_callback
        )
        print(f"Queued {model_id} with {strategy.value} strategy")

    # Monitor progress
    print("\nMonitoring progress...")
    time.sleep(2)  # Let it run for a bit

    # Show statistics
    stats = loader.get_statistics()
    print(f"\nStatistics: {stats}")

    # Show all tasks
    all_progress = loader.get_all_progress()
    print("\nAll tasks:")
    for model_id, progress in all_progress.items():
        print(f"  {model_id}: {progress.state.value} ({progress.progress_percent:.1f}%)")

    # Test caching
    if loader.cache:
        print("\nCache status:")
        for model_id in ["model-lazy", "model-eager"]:
            cached = loader.cache.has_cached(model_id)
            print(f"  {model_id}: {'cached' if cached else 'not cached'}")

    # Shutdown
    loader.shutdown()
    print("\nShutdown complete")
