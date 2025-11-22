"""Lazy Model Loading System for Intellicrack.

This module provides lazy loading capabilities for large AI models,
improving startup time and memory usage by loading models only when needed.

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

import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from .llm_backends import LLMBackend, LLMConfig

logger = logging.getLogger(__name__)


class ModelLoadingStrategy(ABC):
    """Abstract base class for different model loading strategies."""

    @abstractmethod
    def should_preload(self, config: "LLMConfig") -> bool:
        """Determine if a model should be preloaded."""

    @abstractmethod
    def get_load_priority(self, config: "LLMConfig") -> int:
        """Get the loading priority (higher number = higher priority)."""


class DefaultLoadingStrategy(ModelLoadingStrategy):
    """Default loading strategy - load on first use."""

    def should_preload(self, config: "LLMConfig") -> bool:
        """Don't preload by default, but allow API models for quick initialization."""
        # API models are quick to initialize and don't consume much local resources
        return bool(
            hasattr(config, "provider")
            and config.provider.value in ["openai", "anthropic", "ollama"]
        )

    def get_load_priority(self, config: "LLMConfig") -> int:
        """Get load priority based on provider type."""
        # Give API models higher priority since they're faster to initialize
        if hasattr(config, "provider"):
            if config.provider.value in ["openai", "anthropic"]:
                return 10
            if config.provider.value in ["ollama", "local_api"]:
                return 5
        return 0


class SmartLoadingStrategy(ModelLoadingStrategy):
    """Smart loading strategy based on model size and usage patterns."""

    def __init__(
        self,
        preload_small_models: bool = True,
        small_model_threshold_mb: int = 100,
        preload_api_models: bool = True,
    ) -> None:
        """Initialize the smart loading strategy with configurable preloading options.

        Args:
            preload_small_models: Whether to preload models below the size threshold.
            small_model_threshold_mb: Size threshold in MB for considering a model "small".
            preload_api_models: Whether to preload API-based models.

        """
        self.logger = logging.getLogger(f"{__name__}.SmartLoadingStrategy")
        self.preload_small_models = preload_small_models
        self.small_model_threshold_mb = small_model_threshold_mb
        self.preload_api_models = preload_api_models

    def should_preload(self, config: "LLMConfig") -> bool:
        """Preload small models and API-based models."""
        # API models are always quick to initialize
        if config.provider.value in ["openai", "anthropic", "ollama", "local_api"]:
            return self.preload_api_models

        # Check model file size for local models
        if config.model_path and os.path.exists(config.model_path):
            try:
                size_mb = os.path.getsize(config.model_path) / (1024 * 1024)
                if size_mb <= self.small_model_threshold_mb:
                    return self.preload_small_models
            except OSError as e:
                self.logger.error("OS error in lazy_model_loader: %s", e)

        return False

    def get_load_priority(self, config: "LLMConfig") -> int:
        """Higher priority for API models and smaller local models."""
        if config.provider.value in ["openai", "anthropic"]:
            return 100
        if config.provider.value in ["ollama", "local_api"]:
            return 90
        if config.model_path and os.path.exists(config.model_path):
            try:
                size_mb = os.path.getsize(config.model_path) / (1024 * 1024)
                # Smaller models get higher priority
                return max(0, 80 - int(size_mb / 100))
            except OSError as e:
                self.logger.error("OS error in lazy_model_loader: %s", e)

        return 50


class LazyModelWrapper:
    """Wrap that provides lazy loading for LLM backends.

    The actual backend is only initialized when first accessed.
    """

    def __init__(
        self,
        backend_class: type["LLMBackend"],
        config: "LLMConfig",
        preload: bool = False,
        load_callback: Callable[[str, bool], None] | None = None,
    ) -> None:
        """Initialize a lazy-loading wrapper for an LLM backend.

        Args:
            backend_class: The LLM backend class to instantiate lazily.
            config: Configuration for the LLM backend.
            preload: Whether to start loading the model in the background immediately.
            load_callback: Optional callback function called with (model_name, success) after loading.

        """
        self.logger = logging.getLogger(f"{__name__}.LazyModelWrapper")
        self.backend_class = backend_class
        self.config = config
        self.load_callback = load_callback
        self._backend: LLMBackend | None = None
        self._initialized = False
        self._initialization_lock = threading.Lock()
        self._loading = False
        self._load_error: Exception | None = None

        # Metadata for tracking
        self.creation_time = time.time()
        self.last_access_time = None
        self.access_count = 0

        if preload:
            if not (
                os.environ.get("INTELLICRACK_TESTING")
                or os.environ.get("DISABLE_BACKGROUND_THREADS")
            ):
                threading.Thread(target=self._initialize_backend, daemon=True).start()
            else:
                logger.info("Skipping preload background initialization (testing mode)")

    @property
    def is_loaded(self) -> bool:
        """Check if the backend is loaded."""
        return self._initialized and self._backend is not None

    @property
    def is_loading(self) -> bool:
        """Check if the backend is currently loading."""
        return self._loading

    @property
    def has_error(self) -> bool:
        """Check if there was an error loading the backend."""
        return self._load_error is not None

    @property
    def load_error(self) -> Exception | None:
        """Get the loading error if any."""
        return self._load_error

    def _initialize_backend(self) -> bool:
        """Initialize the backend (thread-safe)."""
        with self._initialization_lock:
            if self._initialized:
                return self._backend is not None

            if self._loading:
                # Another thread is loading, wait for it
                while self._loading and not self._initialized:
                    time.sleep(0.1)
                return self._backend is not None

            self._loading = True
            self._load_error = None

            try:
                if self.load_callback:
                    self.load_callback(f"Loading {self.config.model_name}...", False)

                logger.info(f"Initializing lazy-loaded backend: {self.config.model_name}")
                self._backend = self.backend_class(self.config)

                success = self._backend.initialize()
                if not success:
                    self._backend = None
                    raise RuntimeError(f"Failed to initialize backend for {self.config.model_name}")

                logger.info(f"Successfully loaded lazy backend: {self.config.model_name}")

                if self.load_callback:
                    self.load_callback(f"Loaded {self.config.model_name}", True)

                return True

            except Exception as e:
                logger.error(f"Error initializing lazy backend {self.config.model_name}: {e}")
                self._load_error = e
                self._backend = None

                if self.load_callback:
                    self.load_callback(f"Failed to load {self.config.model_name}: {e!s}", True)

                return False

            finally:
                self._initialized = True
                self._loading = False

    def get_backend(self) -> "LLMBackend | None":
        """Get the backend, initializing if necessary."""
        self.last_access_time = time.time()
        self.access_count += 1

        if not self._initialized:
            success = self._initialize_backend()
            if not success:
                return None

        return self._backend

    def unload(self) -> None:
        """Unload the backend to free memory."""
        with self._initialization_lock:
            if self._backend:
                # Call cleanup method if available
                if hasattr(self._backend, "cleanup"):
                    try:
                        self._backend.cleanup()
                    except Exception as e:
                        logger.warning(f"Error during backend cleanup: {e}")

                self._backend = None
                self._initialized = False
                logger.info(f"Unloaded backend: {self.config.model_name}")

    def get_info(self) -> dict[str, Any]:
        """Get information about this lazy wrapper."""
        return {
            "model_name": self.config.model_name,
            "provider": self.config.provider.value,
            "is_loaded": self.is_loaded,
            "is_loading": self.is_loading,
            "has_error": self.has_error,
            "access_count": self.access_count,
            "last_access": self.last_access_time,
            "creation_time": self.creation_time,
            "memory_usage": self._estimate_memory_usage(),
        }

    def _estimate_memory_usage(self) -> str:
        """Estimate memory usage of the loaded model."""
        if not self.is_loaded:
            return "Not loaded"

        # Try to get actual memory usage if possible
        try:
            if hasattr(self._backend, "get_memory_usage"):
                return self._backend.get_memory_usage()
        except Exception as e:
            logger.debug(f"Could not get memory usage from backend: {e}")

        # Estimate based on model type and size
        if self.config.model_path and os.path.exists(self.config.model_path):
            try:
                size_mb = os.path.getsize(self.config.model_path) / (1024 * 1024)
                return f"~{size_mb:.1f} MB"
            except OSError as e:
                self.logger.error("OS error in lazy_model_loader: %s", e)

        return "Unknown"


class LazyModelManager:
    """Manager for lazy-loaded models.

    Handles loading strategies, memory management, and model lifecycle.
    """

    def __init__(self, loading_strategy: ModelLoadingStrategy | None = None) -> None:
        """Initialize the lazy model manager with optional loading strategy.

        Args:
            loading_strategy: Strategy for determining model loading behavior.
                            Defaults to DefaultLoadingStrategy if not provided.

        """
        self.loading_strategy = loading_strategy or DefaultLoadingStrategy()
        self.models: dict[str, LazyModelWrapper] = {}
        self._access_lock = threading.Lock()
        self.load_callbacks: list[Callable[[str, bool], None]] = []

        # Memory management settings
        self.max_loaded_models = 3  # Maximum models to keep loaded
        self.memory_cleanup_threshold = 0.8  # Start cleanup at 80% usage
        self.idle_unload_time = 1800  # Unload after 30 minutes of inactivity

        # Start background cleanup thread (skip during testing)
        if not (
            os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS")
        ):
            self._cleanup_thread = threading.Thread(target=self._background_cleanup, daemon=True)
            self._cleanup_thread.start()
            logger.info("Started background cleanup thread")
        else:
            logger.info("Skipping background cleanup thread (testing mode)")
            self._cleanup_thread = None

    def add_load_callback(self, callback: Callable[[str, bool], None]) -> None:
        """Add a callback for loading progress updates."""
        self.load_callbacks.append(callback)

    def _notify_load_callback(self, message: str, finished: bool) -> None:
        """Notify all load callbacks."""
        for callback in self.load_callbacks:
            try:
                callback(message, finished)
            except Exception as e:
                logger.warning(f"Error in load callback: {e}")

    def register_model(
        self, model_id: str, backend_class: type["LLMBackend"], config: "LLMConfig"
    ) -> LazyModelWrapper:
        """Register a model for lazy loading."""
        with self._access_lock:
            preload = self.loading_strategy.should_preload(config)

            wrapper = LazyModelWrapper(
                backend_class=backend_class,
                config=config,
                preload=preload,
                load_callback=self._notify_load_callback,
            )

            self.models[model_id] = wrapper
            logger.info(f"Registered lazy model: {model_id} (preload: {preload})")

            return wrapper

    def get_model(self, model_id: str) -> "LLMBackend | None":
        """Get a model backend, loading if necessary."""
        with self._access_lock:
            if model_id not in self.models:
                logger.warning(f"Model not found: {model_id}")
                return None

            wrapper = self.models[model_id]
            backend = wrapper.get_backend()

            # Trigger memory cleanup if needed
            self._maybe_cleanup_memory()

            return backend

    def unload_model(self, model_id: str) -> bool:
        """Manually unload a specific model."""
        with self._access_lock:
            if model_id not in self.models:
                return False

            self.models[model_id].unload()
            logger.info(f"Manually unloaded model: {model_id}")
            return True

    def unload_all(self) -> None:
        """Unload all models."""
        with self._access_lock:
            for _, wrapper in self.models.items():
                wrapper.unload()
            logger.info("Unloaded all models")

    def get_model_info(self, model_id: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        """Get information about models."""
        with self._access_lock:
            if model_id:
                return self.models[model_id].get_info() if model_id in self.models else {}
            return [wrapper.get_info() for wrapper in self.models.values()]

    def get_loaded_models(self) -> list[str]:
        """Get list of currently loaded model IDs."""
        with self._access_lock:
            return [model_id for model_id, wrapper in self.models.items() if wrapper.is_loaded]

    def _maybe_cleanup_memory(self) -> None:
        """Check if memory cleanup is needed and perform it."""
        loaded_count = len(self.get_loaded_models())

        if loaded_count > self.max_loaded_models:
            self._cleanup_least_used_models(loaded_count - self.max_loaded_models)

    def _cleanup_least_used_models(self, count_to_unload: int) -> None:
        """Unload the least recently used models."""
        loaded_models = [
            (wrapper.last_access_time, model_id, wrapper)
            for model_id, wrapper in self.models.items()
            if wrapper.is_loaded and wrapper.last_access_time
        ]
        # Sort by access time (oldest first)
        loaded_models.sort(key=lambda x: x[0])

        # Unload the oldest models
        for i in range(min(count_to_unload, len(loaded_models))):
            _, model_id, wrapper = loaded_models[i]
            wrapper.unload()
            logger.info(f"Auto-unloaded least used model: {model_id}")

    def _background_cleanup(self) -> None:
        """Background thread for periodic cleanup."""
        while True:
            try:
                time.sleep(300)  # Check every 5 minutes
                self._cleanup_idle_models()
            except Exception as e:
                logger.error(f"Error in background cleanup: {e}")

    def _cleanup_idle_models(self) -> None:
        """Unload models that have been idle for too long."""
        current_time = time.time()

        with self._access_lock:
            for model_id, wrapper in list(self.models.items()):
                if (
                    wrapper.is_loaded
                    and wrapper.last_access_time
                    and current_time - wrapper.last_access_time > self.idle_unload_time
                ):
                    wrapper.unload()
                    logger.info(f"Auto-unloaded idle model: {model_id}")


# Global lazy model manager instance
_lazy_manager: LazyModelManager | None = None


def get_lazy_manager() -> LazyModelManager:
    """Get the global lazy model manager instance."""
    global _lazy_manager
    if _lazy_manager is None:
        # Use smart loading strategy by default
        strategy = SmartLoadingStrategy()
        _lazy_manager = LazyModelManager(strategy)
    return _lazy_manager


def configure_lazy_loading(
    max_loaded_models: int = 3,
    idle_unload_time: int = 1800,
    loading_strategy: ModelLoadingStrategy | None = None,
) -> None:
    """Configure global lazy loading settings."""
    manager = get_lazy_manager()
    manager.max_loaded_models = max_loaded_models
    manager.idle_unload_time = idle_unload_time

    if loading_strategy:
        manager.loading_strategy = loading_strategy


def register_lazy_model(
    model_id: str, backend_class: type["LLMBackend"], config: "LLMConfig"
) -> LazyModelWrapper:
    """Register a model for lazy loading."""
    return get_lazy_manager().register_model(model_id, backend_class, config)


def get_lazy_model(model_id: str) -> "LLMBackend | None":
    """Get a lazy-loaded model."""
    return get_lazy_manager().get_model(model_id)
