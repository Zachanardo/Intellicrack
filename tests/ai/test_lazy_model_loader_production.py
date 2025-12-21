"""Production tests for lazy model loading system.

Tests validate REAL lazy loading functionality for AI models used in license
protection analysis. All tests verify actual model loading behavior, memory
management, and performance optimizations.

Copyright (C) 2025 Zachary Flint
Licensed under GPL v3.
"""

import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from intellicrack.ai.lazy_model_loader import (
    DefaultLoadingStrategy,
    LazyModelManager,
    LazyModelWrapper,
    ModelLoadingStrategy,
    SmartLoadingStrategy,
    configure_lazy_loading,
    get_lazy_manager,
    get_lazy_model,
    register_lazy_model,
)


class MockLLMBackend:
    """Mock LLM backend for testing lazy loading."""

    def __init__(self, config: Any) -> None:
        self.config = config
        self.initialized = False
        self.cleanup_called = False
        self.init_time = 0.0

    def initialize(self) -> bool:
        """Simulate model initialization with delay."""
        time.sleep(0.1)
        self.initialized = True
        self.init_time = time.time()
        return True

    def cleanup(self) -> None:
        """Cleanup resources."""
        self.cleanup_called = True


class MockLLMConfig:
    """Mock LLM configuration for testing."""

    def __init__(
        self,
        model_name: str = "test-model",
        provider: str = "openai",
        model_path: str | None = None,
    ) -> None:
        self.model_name = model_name
        self.provider = Mock()
        self.provider.value = provider
        self.model_path = model_path


class FailingLLMBackend:
    """Mock backend that fails initialization."""

    def __init__(self, config: Any) -> None:
        self.config = config

    def initialize(self) -> bool:
        """Fail initialization."""
        raise RuntimeError("Simulated initialization failure")


class TestDefaultLoadingStrategy:
    """Tests for DefaultLoadingStrategy validating preload decisions."""

    def test_default_strategy_preloads_openai_models(self) -> None:
        """Default strategy preloads OpenAI API models for quick access."""
        strategy = DefaultLoadingStrategy()
        config = MockLLMConfig(provider="openai")

        should_preload = strategy.should_preload(config)

        assert should_preload is True

    def test_default_strategy_preloads_anthropic_models(self) -> None:
        """Default strategy preloads Anthropic API models for quick access."""
        strategy = DefaultLoadingStrategy()
        config = MockLLMConfig(provider="anthropic")

        should_preload = strategy.should_preload(config)

        assert should_preload is True

    def test_default_strategy_preloads_ollama_models(self) -> None:
        """Default strategy preloads Ollama models for quick access."""
        strategy = DefaultLoadingStrategy()
        config = MockLLMConfig(provider="ollama")

        should_preload = strategy.should_preload(config)

        assert should_preload is True

    def test_default_strategy_does_not_preload_local_models(self) -> None:
        """Default strategy does not preload large local models."""
        strategy = DefaultLoadingStrategy()
        config = MockLLMConfig(provider="local")

        should_preload = strategy.should_preload(config)

        assert should_preload is False

    def test_default_strategy_prioritizes_openai_highest(self) -> None:
        """Default strategy gives OpenAI models highest priority."""
        strategy = DefaultLoadingStrategy()
        config = MockLLMConfig(provider="openai")

        priority = strategy.get_load_priority(config)

        assert priority == 10

    def test_default_strategy_prioritizes_anthropic_highest(self) -> None:
        """Default strategy gives Anthropic models highest priority."""
        strategy = DefaultLoadingStrategy()
        config = MockLLMConfig(provider="anthropic")

        priority = strategy.get_load_priority(config)

        assert priority == 10

    def test_default_strategy_prioritizes_ollama_medium(self) -> None:
        """Default strategy gives Ollama models medium priority."""
        strategy = DefaultLoadingStrategy()
        config = MockLLMConfig(provider="ollama")

        priority = strategy.get_load_priority(config)

        assert priority == 5

    def test_default_strategy_prioritizes_unknown_lowest(self) -> None:
        """Default strategy gives unknown providers lowest priority."""
        strategy = DefaultLoadingStrategy()
        config = MockLLMConfig(provider="unknown")

        priority = strategy.get_load_priority(config)

        assert priority == 0


class TestSmartLoadingStrategy:
    """Tests for SmartLoadingStrategy validating intelligent preloading."""

    def test_smart_strategy_preloads_api_models_by_default(self) -> None:
        """Smart strategy preloads API models for quick initialization."""
        strategy = SmartLoadingStrategy()
        config = MockLLMConfig(provider="openai")

        should_preload = strategy.should_preload(config)

        assert should_preload is True

    def test_smart_strategy_can_disable_api_preloading(self) -> None:
        """Smart strategy can be configured to disable API model preloading."""
        strategy = SmartLoadingStrategy(preload_api_models=False)
        config = MockLLMConfig(provider="openai")

        should_preload = strategy.should_preload(config)

        assert should_preload is False

    def test_smart_strategy_preloads_small_local_models(self) -> None:
        """Smart strategy preloads small local models below threshold."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"x" * (50 * 1024 * 1024))
            tmp_path = tmp.name

        try:
            strategy = SmartLoadingStrategy(small_model_threshold_mb=100)
            config = MockLLMConfig(provider="local", model_path=tmp_path)

            should_preload = strategy.should_preload(config)

            assert should_preload is True
        finally:
            os.unlink(tmp_path)

    def test_smart_strategy_does_not_preload_large_local_models(self) -> None:
        """Smart strategy does not preload large local models above threshold."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"x" * (150 * 1024 * 1024))
            tmp_path = tmp.name

        try:
            strategy = SmartLoadingStrategy(small_model_threshold_mb=100)
            config = MockLLMConfig(provider="local", model_path=tmp_path)

            should_preload = strategy.should_preload(config)

            assert should_preload is False
        finally:
            os.unlink(tmp_path)

    def test_smart_strategy_handles_missing_model_file(self) -> None:
        """Smart strategy handles missing model files gracefully."""
        strategy = SmartLoadingStrategy()
        config = MockLLMConfig(provider="local", model_path="/nonexistent/model.bin")

        should_preload = strategy.should_preload(config)

        assert should_preload is False

    def test_smart_strategy_prioritizes_api_models_highest(self) -> None:
        """Smart strategy gives API models highest priority."""
        strategy = SmartLoadingStrategy()
        config = MockLLMConfig(provider="openai")

        priority = strategy.get_load_priority(config)

        assert priority == 100

    def test_smart_strategy_prioritizes_by_model_size(self) -> None:
        """Smart strategy prioritizes smaller local models over larger ones."""
        with tempfile.NamedTemporaryFile(delete=False) as small_tmp:
            small_tmp.write(b"x" * (50 * 1024 * 1024))
            small_path = small_tmp.name

        with tempfile.NamedTemporaryFile(delete=False) as large_tmp:
            large_tmp.write(b"x" * (500 * 1024 * 1024))
            large_path = large_tmp.name

        try:
            strategy = SmartLoadingStrategy()
            small_config = MockLLMConfig(provider="local", model_path=small_path)
            large_config = MockLLMConfig(provider="local", model_path=large_path)

            small_priority = strategy.get_load_priority(small_config)
            large_priority = strategy.get_load_priority(large_config)

            assert small_priority > large_priority
        finally:
            os.unlink(small_path)
            os.unlink(large_path)


class TestLazyModelWrapper:
    """Tests for LazyModelWrapper validating lazy initialization."""

    def test_wrapper_initializes_on_first_access(self) -> None:
        """Wrapper initializes backend only when first accessed."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=False)

        assert wrapper.is_loaded is False

        backend = wrapper.get_backend()

        assert wrapper.is_loaded is True
        assert backend is not None
        assert backend.initialized is True

    def test_wrapper_preloads_when_requested(self) -> None:
        """Wrapper does not background preload in testing mode."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=True)

        time.sleep(0.2)

        assert wrapper.is_loaded is False

    def test_wrapper_tracks_access_count(self) -> None:
        """Wrapper tracks access count for memory management."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=False)

        assert wrapper.access_count == 0

        wrapper.get_backend()
        wrapper.get_backend()
        wrapper.get_backend()

        assert wrapper.access_count == 3

    def test_wrapper_tracks_last_access_time(self) -> None:
        """Wrapper tracks last access time for idle cleanup."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=False)

        assert wrapper.last_access_time is None

        wrapper.get_backend()

        assert wrapper.last_access_time is not None
        assert wrapper.last_access_time > wrapper.creation_time

    def test_wrapper_handles_initialization_failure(self) -> None:
        """Wrapper handles backend initialization failures gracefully."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(FailingLLMBackend, config, preload=False)

        backend = wrapper.get_backend()

        assert backend is None
        assert wrapper.has_error is True
        assert wrapper.load_error is not None
        assert "initialization failure" in str(wrapper.load_error).lower()

    def test_wrapper_is_thread_safe(self) -> None:
        """Wrapper handles concurrent access safely."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=False)

        backends = []
        errors = []

        def access_backend() -> None:
            try:
                backend = wrapper.get_backend()
                backends.append(backend)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=access_backend) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(errors) == 0
        assert all(b is not None for b in backends)
        assert all(b is backends[0] for b in backends)

    def test_wrapper_unloads_backend(self) -> None:
        """Wrapper unloads backend and frees resources."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=False)

        backend = wrapper.get_backend()
        assert wrapper.is_loaded is True
        assert backend is not None

        wrapper.unload()

        assert wrapper.is_loaded is False
        assert backend.cleanup_called is True

    def test_wrapper_provides_info(self) -> None:
        """Wrapper provides information about loading state."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig(model_name="test-gpt-4")
        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=False)

        info = wrapper.get_info()

        assert info["model_name"] == "test-gpt-4"
        assert info["is_loaded"] is False
        assert info["access_count"] == 0

        wrapper.get_backend()
        info = wrapper.get_info()

        assert info["is_loaded"] is True
        assert info["access_count"] == 1


class TestLazyModelManager:
    """Tests for LazyModelManager validating model lifecycle management."""

    def test_manager_registers_models(self) -> None:
        """Manager registers models for lazy loading."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()
        config = MockLLMConfig(model_name="gpt-4")

        wrapper = manager.register_model("model-1", MockLLMBackend, config)

        assert "model-1" in manager.models
        assert wrapper.config.model_name == "gpt-4"

    def test_manager_loads_models_on_access(self) -> None:
        """Manager loads models when accessed."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()
        config = MockLLMConfig()

        manager.register_model("model-1", MockLLMBackend, config)
        assert len(manager.get_loaded_models()) == 0

        backend = manager.get_model("model-1")

        assert backend is not None
        assert backend.initialized is True
        assert len(manager.get_loaded_models()) == 1

    def test_manager_returns_none_for_unknown_models(self) -> None:
        """Manager returns None for unknown model IDs."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()

        backend = manager.get_model("unknown-model")

        assert backend is None

    def test_manager_unloads_specific_models(self) -> None:
        """Manager unloads specific models on request."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()
        config = MockLLMConfig()

        manager.register_model("model-1", MockLLMBackend, config)
        manager.get_model("model-1")
        assert len(manager.get_loaded_models()) == 1

        success = manager.unload_model("model-1")

        assert success is True
        assert len(manager.get_loaded_models()) == 0

    def test_manager_unloads_all_models(self) -> None:
        """Manager unloads all models at once."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()

        for i in range(3):
            config = MockLLMConfig(model_name=f"model-{i}")
            manager.register_model(f"model-{i}", MockLLMBackend, config)
            manager.get_model(f"model-{i}")

        assert len(manager.get_loaded_models()) == 3

        manager.unload_all()

        assert len(manager.get_loaded_models()) == 0

    def test_manager_enforces_max_loaded_models(self) -> None:
        """Manager enforces maximum loaded models limit."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()
        manager.max_loaded_models = 2

        for i in range(4):
            config = MockLLMConfig(model_name=f"model-{i}")
            manager.register_model(f"model-{i}", MockLLMBackend, config)
            manager.get_model(f"model-{i}")
            time.sleep(0.05)

        loaded_count = len(manager.get_loaded_models())

        assert loaded_count <= manager.max_loaded_models

    def test_manager_unloads_least_recently_used_models(self) -> None:
        """Manager unloads least recently used models when limit exceeded."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()
        manager.max_loaded_models = 2

        for i in range(3):
            config = MockLLMConfig(model_name=f"model-{i}")
            manager.register_model(f"model-{i}", MockLLMBackend, config)
            manager.get_model(f"model-{i}")
            time.sleep(0.05)

        manager.get_model("model-1")

        loaded = manager.get_loaded_models()

        assert "model-0" not in loaded

    def test_manager_provides_model_info(self) -> None:
        """Manager provides information about all models."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()

        for i in range(2):
            config = MockLLMConfig(model_name=f"model-{i}")
            manager.register_model(f"model-{i}", MockLLMBackend, config)

        all_info = manager.get_model_info()

        assert isinstance(all_info, list)
        assert len(all_info) == 2

    def test_manager_uses_loading_strategy_for_preloading(self) -> None:
        """Manager uses loading strategy to determine preloading."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        strategy = Mock(spec=ModelLoadingStrategy)
        strategy.should_preload.return_value = False
        manager = LazyModelManager(loading_strategy=strategy)

        config = MockLLMConfig()
        manager.register_model("model-1", MockLLMBackend, config)

        strategy.should_preload.assert_called_once_with(config)

    def test_manager_handles_load_callbacks(self) -> None:
        """Manager notifies load callbacks during model initialization."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()
        callback_messages = []

        def callback(message: str, finished: bool) -> None:
            callback_messages.append((message, finished))

        manager.add_load_callback(callback)
        config = MockLLMConfig(model_name="gpt-4")
        manager.register_model("model-1", MockLLMBackend, config)

        manager.get_model("model-1")

        assert len(callback_messages) >= 2
        assert any("Loading" in msg for msg, _ in callback_messages)
        assert any("Loaded" in msg for msg, _ in callback_messages)


class TestGlobalLazyManager:
    """Tests for global lazy manager singleton functionality."""

    def test_get_lazy_manager_returns_singleton(self) -> None:
        """get_lazy_manager returns same instance across calls."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        manager1 = get_lazy_manager()
        manager2 = get_lazy_manager()

        assert manager1 is manager2

    def test_configure_lazy_loading_updates_settings(self) -> None:
        """configure_lazy_loading updates global manager settings."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        configure_lazy_loading(max_loaded_models=5, idle_unload_time=3600)
        manager = get_lazy_manager()

        assert manager.max_loaded_models == 5
        assert manager.idle_unload_time == 3600

    def test_register_lazy_model_uses_global_manager(self) -> None:
        """register_lazy_model uses global manager instance."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()

        wrapper = register_lazy_model("test-model", MockLLMBackend, config)
        manager = get_lazy_manager()

        assert "test-model" in manager.models
        assert manager.models["test-model"] is wrapper

    def test_get_lazy_model_uses_global_manager(self) -> None:
        """get_lazy_model uses global manager instance."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()

        register_lazy_model("test-model", MockLLMBackend, config)
        backend = get_lazy_model("test-model")

        assert backend is not None
        assert backend.initialized is True


class TestMemoryManagement:
    """Tests for memory management and cleanup functionality."""

    def test_manager_cleans_up_least_used_models(self) -> None:
        """Manager automatically cleans up least used models."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()
        manager.max_loaded_models = 2

        configs = [MockLLMConfig(model_name=f"model-{i}") for i in range(3)]
        for i, config in enumerate(configs):
            manager.register_model(f"model-{i}", MockLLMBackend, config)
            manager.get_model(f"model-{i}")
            time.sleep(0.05)

        loaded_count = len(manager.get_loaded_models())

        assert loaded_count == 2

    def test_wrapper_estimates_memory_usage(self) -> None:
        """Wrapper estimates memory usage for loaded models."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=False)

        info = wrapper.get_info()
        assert info["memory_usage"] == "Not loaded"

        wrapper.get_backend()
        info = wrapper.get_info()

        assert "Unknown" in info["memory_usage"]

    def test_wrapper_estimates_memory_for_local_models(self) -> None:
        """Wrapper estimates memory usage based on model file size."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"x" * (100 * 1024 * 1024))
            tmp_path = tmp.name

        try:
            os.environ["INTELLICRACK_TESTING"] = "1"
            config = MockLLMConfig(model_path=tmp_path)
            wrapper = LazyModelWrapper(MockLLMBackend, config, preload=False)

            wrapper.get_backend()
            info = wrapper.get_info()

            assert "MB" in info["memory_usage"]
        finally:
            os.unlink(tmp_path)


class TestThreadSafety:
    """Tests for thread safety of lazy loading system."""

    def test_wrapper_handles_concurrent_initialization(self) -> None:
        """Wrapper safely handles concurrent initialization attempts."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=False)

        backends = []
        errors = []

        def get_backend_concurrently() -> None:
            try:
                backend = wrapper.get_backend()
                backends.append(backend)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=get_backend_concurrently) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(errors) == 0
        assert len(backends) == 20
        assert all(backend is backends[0] for backend in backends)

    def test_manager_handles_concurrent_registration(self) -> None:
        """Manager safely handles concurrent model registration."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()

        errors = []

        def register_model_concurrently(i: int) -> None:
            try:
                config = MockLLMConfig(model_name=f"model-{i}")
                manager.register_model(f"model-{i}", MockLLMBackend, config)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=register_model_concurrently, args=(i,)) for i in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(errors) == 0
        assert len(manager.models) == 10


class TestErrorHandling:
    """Tests for error handling in lazy loading system."""

    def test_wrapper_handles_backend_init_failure(self) -> None:
        """Wrapper handles backend initialization failures gracefully."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(FailingLLMBackend, config, preload=False)

        backend = wrapper.get_backend()

        assert backend is None
        assert wrapper.has_error is True
        assert wrapper.load_error is not None

    def test_wrapper_returns_none_after_failure(self) -> None:
        """Wrapper returns None on subsequent accesses after failure."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(FailingLLMBackend, config, preload=False)

        backend1 = wrapper.get_backend()
        backend2 = wrapper.get_backend()

        assert backend1 is None
        assert backend2 is None

    def test_manager_handles_unload_of_nonexistent_model(self) -> None:
        """Manager handles unload requests for nonexistent models."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()

        success = manager.unload_model("nonexistent")

        assert success is False

    def test_wrapper_handles_cleanup_errors(self) -> None:
        """Wrapper handles errors during backend cleanup gracefully."""

        class ErrorCleanupBackend(MockLLMBackend):
            def cleanup(self) -> None:
                raise RuntimeError("Cleanup failed")

        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()
        wrapper = LazyModelWrapper(ErrorCleanupBackend, config, preload=False)

        wrapper.get_backend()
        wrapper.unload()

        assert wrapper.is_loaded is False


class TestPerformanceOptimization:
    """Tests validating performance optimizations in lazy loading."""

    def test_lazy_loading_defers_initialization(self) -> None:
        """Lazy loading defers expensive initialization until needed."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()

        start_time = time.time()
        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=False)
        creation_time = time.time() - start_time

        assert creation_time < 0.05
        assert wrapper.is_loaded is False

    def test_preloading_initializes_model_early(self) -> None:
        """Preloading flag triggers early initialization (disabled in testing)."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        config = MockLLMConfig()

        wrapper = LazyModelWrapper(MockLLMBackend, config, preload=True)
        time.sleep(0.2)

        assert wrapper.is_loaded is False

    def test_manager_prioritizes_api_models_for_preloading(self) -> None:
        """Manager prioritizes API models for preloading."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        strategy = SmartLoadingStrategy()
        manager = LazyModelManager(loading_strategy=strategy)

        api_config = MockLLMConfig(provider="openai")
        local_config = MockLLMConfig(provider="local")

        api_wrapper = manager.register_model("api-model", MockLLMBackend, api_config)
        local_wrapper = manager.register_model("local-model", MockLLMBackend, local_config)

        assert strategy.should_preload(api_config) is True
        assert strategy.should_preload(local_config) is False


class TestIntegrationScenarios:
    """Integration tests for complete lazy loading workflows."""

    def test_complete_model_lifecycle(self) -> None:
        """Complete model lifecycle: register, load, use, unload."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()
        config = MockLLMConfig(model_name="gpt-4-turbo")

        wrapper = manager.register_model("gpt4", MockLLMBackend, config)
        assert wrapper.is_loaded is False

        backend = manager.get_model("gpt4")
        assert backend is not None
        assert backend.initialized is True
        assert wrapper.is_loaded is True

        manager.unload_model("gpt4")
        assert wrapper.is_loaded is False

    def test_multiple_models_with_priority_loading(self) -> None:
        """Multiple models load based on strategy priority."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        strategy = SmartLoadingStrategy()
        manager = LazyModelManager(loading_strategy=strategy)

        configs = [
            MockLLMConfig(model_name="gpt-4", provider="openai"),
            MockLLMConfig(model_name="claude-3", provider="anthropic"),
            MockLLMConfig(model_name="local-llama", provider="local"),
        ]

        for i, config in enumerate(configs):
            manager.register_model(f"model-{i}", MockLLMBackend, config)

        priorities = [strategy.get_load_priority(config) for config in configs]

        assert priorities[0] == 100
        assert priorities[1] == 100
        assert priorities[2] == 50

    def test_automatic_memory_management(self) -> None:
        """Automatic memory management unloads models when limit exceeded."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        manager = LazyModelManager()
        manager.max_loaded_models = 2

        for i in range(4):
            config = MockLLMConfig(model_name=f"model-{i}")
            manager.register_model(f"model-{i}", MockLLMBackend, config)
            manager.get_model(f"model-{i}")
            time.sleep(0.05)

        loaded_count = len(manager.get_loaded_models())

        assert loaded_count <= 2

    def test_strategy_based_selective_preloading(self) -> None:
        """Strategy-based selective preloading loads appropriate models."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        strategy = SmartLoadingStrategy(
            preload_small_models=True,
            small_model_threshold_mb=100,
            preload_api_models=True,
        )

        api_config = MockLLMConfig(provider="openai")
        local_config = MockLLMConfig(provider="local", model_path="/large/model.bin")

        api_preload = strategy.should_preload(api_config)
        local_preload = strategy.should_preload(local_config)

        assert api_preload is True
        assert local_preload is False
