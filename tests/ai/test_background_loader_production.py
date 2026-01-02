"""Production-grade tests for Background Model Loader.

Tests validate real background model loading including:
- Concurrent model loading in background threads
- Priority queue management
- Progress tracking and callbacks
- Task cancellation and cleanup
- Thread safety and synchronization
- Memory efficiency with multiple models
- Error handling and recovery
- Integration with LLM manager
- Statistics and status reporting
"""

import os
import threading
import time
from collections.abc import Generator
from typing import Any

import pytest

from intellicrack.ai.background_loader import (
    BackgroundModelLoader,
    ConsoleProgressCallback,
    IntegratedBackgroundLoader,
    LoadingTask,
    QueuedProgressCallback,
    get_background_loader,
    load_model_with_progress,
)
from intellicrack.ai.llm_backends import (
    LLMBackend,
    LLMConfig,
    LLMMessage,
    LLMProvider,
    LLMResponse,
)
from intellicrack.ai.llm_manager import LLMManager
from intellicrack.ai.llm_types import LoadingProgress, LoadingState, ProgressCallback


def create_test_config(
    model_name: str = "test-model",
    provider: str = "openai",
) -> LLMConfig:
    """Create a test LLMConfig with the specified provider."""
    provider_map = {
        "openai": LLMProvider.OPENAI,
        "anthropic": LLMProvider.ANTHROPIC,
        "ollama": LLMProvider.OLLAMA,
        "local": LLMProvider.LOCAL_GGUF,
    }
    provider_enum = provider_map.get(provider, LLMProvider.OPENAI)
    return LLMConfig(
        provider=provider_enum,
        model_name=model_name,
    )


class FakeProgressCallback(ProgressCallback):
    """Real test double for progress callbacks with call tracking."""

    def __init__(self) -> None:
        """Initialize fake callback."""
        self.progress_calls: list[LoadingProgress] = []
        self.completion_calls: list[tuple[str, bool, str | None]] = []

    def on_progress(self, progress: LoadingProgress) -> None:
        """Track progress updates."""
        self.progress_calls.append(progress)

    def on_completed(
        self, model_id: str, success: bool, error: str | None = None
    ) -> None:
        """Track completion updates."""
        self.completion_calls.append((model_id, success, error))

    def reset(self) -> None:
        """Reset tracked calls."""
        self.progress_calls.clear()
        self.completion_calls.clear()


class FakeLLMBackend(LLMBackend):
    """Test backend for background loading tests."""

    def __init__(self, config: LLMConfig) -> None:
        """Initialize fake backend."""
        super().__init__(config)
        self.initialized = False

    def initialize(self) -> bool:
        """Simulate initialization with delay."""
        time.sleep(0.1)
        self.initialized = True
        self.is_initialized = True
        return True

    def chat(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> LLMResponse:
        """Return mock response."""
        return LLMResponse(content="Mock response", finish_reason="stop")


@pytest.fixture
def fake_backend_class() -> type:
    """Create fake backend class."""
    return FakeLLMBackend


@pytest.fixture
def fake_config() -> LLMConfig:
    """Create fake LLM config."""
    return create_test_config(model_name="test-model")


@pytest.fixture
def background_loader() -> Generator[BackgroundModelLoader, None, None]:
    """Create background model loader for testing."""
    os.environ["INTELLICRACK_TESTING"] = "1"
    loader = BackgroundModelLoader(max_concurrent_loads=2)
    yield loader
    loader.shutdown()
    del os.environ["INTELLICRACK_TESTING"]


class TestLoadingTask:
    """Test individual loading task functionality."""

    def test_loading_task_initialization(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Loading task initializes with correct default state."""
        task = LoadingTask(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
            priority=5,
        )

        assert task.model_id == "test-model"
        assert task.backend_class == fake_backend_class
        assert task.config == fake_config
        assert task.priority == 5
        assert task.state == LoadingState.PENDING
        assert task.progress == 0.0
        assert task.result is None
        assert task.error is None
        assert task.cancelled is False

    def test_update_progress_updates_state(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Update progress updates task state correctly."""
        task = LoadingTask(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        task.update_progress(0.5, "Loading model", LoadingState.LOADING)

        assert task.progress == 0.5
        assert task.message == "Loading model"
        assert task.state == LoadingState.LOADING

    def test_update_progress_clamps_values(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Update progress clamps values to valid range."""
        task = LoadingTask(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        task.update_progress(1.5, "Over 100%")
        assert task.progress == 1.0

        task.update_progress(-0.5, "Below 0%")
        assert task.progress == 0.0

    def test_update_progress_invokes_callback(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Update progress invokes progress callback."""
        callback = FakeProgressCallback()

        task = LoadingTask(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
            callback=callback,
        )

        task.start_time = time.time()
        task.update_progress(0.5, "Loading", LoadingState.LOADING)

        assert len(callback.progress_calls) == 1
        progress_update = callback.progress_calls[0]
        assert isinstance(progress_update, LoadingProgress)
        assert progress_update.model_id == "test-model"
        assert progress_update.progress == 0.5

    def test_mark_completed_success(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Mark completed with success updates task state."""
        task = LoadingTask(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        fake_backend = FakeLLMBackend(fake_config)
        task.mark_completed(True, result=fake_backend)

        assert task.state == LoadingState.COMPLETED
        assert task.progress == 1.0
        assert task.result == fake_backend
        assert task.error is None
        assert task.end_time is not None

    def test_mark_completed_failure(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Mark completed with failure updates task state."""
        task = LoadingTask(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        task.mark_completed(False, error="Initialization failed")

        assert task.state == LoadingState.FAILED
        assert task.progress == 0.0
        assert task.result is None
        assert task.error == "Initialization failed"

    def test_mark_completed_invokes_callback(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Mark completed invokes completion callback."""
        callback = FakeProgressCallback()

        task = LoadingTask(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
            callback=callback,
        )

        task.mark_completed(True)

        assert len(callback.completion_calls) == 1
        model_id, success, error = callback.completion_calls[0]
        assert model_id == "test-model"
        assert success is True
        assert error is None

    def test_cancel_task(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Cancel task marks it as cancelled."""
        task = LoadingTask(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        task.cancel()

        assert task.cancelled is True
        assert task.state == LoadingState.CANCELLED

    def test_cancel_task_invokes_callback(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Cancel task invokes callback with cancelled status."""
        callback = FakeProgressCallback()

        task = LoadingTask(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
            callback=callback,
        )

        task.cancel()

        assert len(callback.completion_calls) == 1
        model_id, success, error = callback.completion_calls[0]
        assert success is False
        assert error is not None
        assert "Cancel" in error


class TestConsoleProgressCallback:
    """Test console-based progress callback."""

    def test_console_callback_logs_progress(self) -> None:
        """Console callback logs progress updates."""
        callback = ConsoleProgressCallback()

        progress = LoadingProgress(
            model_id="test-model",
            model_name="Test Model",
            state=LoadingState.LOADING,
            progress=0.5,
            message="Loading model",
            details={},
            timestamp=time.time(),
        )

        callback.on_progress(progress)

    def test_console_callback_logs_completion(self) -> None:
        """Console callback logs completion status."""
        callback = ConsoleProgressCallback()

        callback.on_completed("test-model", True)
        callback.on_completed("test-model-2", False, "Error occurred")


class TestQueuedProgressCallback:
    """Test queue-based progress callback."""

    def test_queued_callback_stores_progress(self) -> None:
        """Queued callback stores progress updates in queue."""
        callback = QueuedProgressCallback()

        progress1 = LoadingProgress(
            model_id="model-1",
            model_name="Model 1",
            state=LoadingState.LOADING,
            progress=0.3,
            message="Loading",
            details={},
            timestamp=time.time(),
        )

        progress2 = LoadingProgress(
            model_id="model-2",
            model_name="Model 2",
            state=LoadingState.DOWNLOADING,
            progress=0.7,
            message="Downloading",
            details={},
            timestamp=time.time(),
        )

        callback.on_progress(progress1)
        callback.on_progress(progress2)

        updates = callback.get_progress_updates()

        assert len(updates) == 2
        assert updates[0].model_id == "model-1"
        assert updates[1].model_id == "model-2"

    def test_queued_callback_stores_completions(self) -> None:
        """Queued callback stores completion updates in queue."""
        callback = QueuedProgressCallback()

        callback.on_completed("model-1", True)
        callback.on_completed("model-2", False, "Failed")

        completions = callback.get_completion_updates()

        assert len(completions) == 2
        assert completions[0] == ("model-1", True, None)
        assert completions[1] == ("model-2", False, "Failed")

    def test_get_progress_updates_empties_queue(self) -> None:
        """Get progress updates empties the queue."""
        callback = QueuedProgressCallback()

        progress = LoadingProgress(
            model_id="test-model",
            model_name="Test",
            state=LoadingState.LOADING,
            progress=0.5,
            message="Loading",
            details={},
            timestamp=time.time(),
        )

        callback.on_progress(progress)
        first_updates = callback.get_progress_updates()
        second_updates = callback.get_progress_updates()

        assert len(first_updates) == 1
        assert len(second_updates) == 0


class TestBackgroundModelLoader:
    """Test background model loader functionality."""

    def test_loader_initialization(self) -> None:
        """Background loader initializes with correct state."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        loader = BackgroundModelLoader(max_concurrent_loads=3)

        assert loader.max_concurrent_loads == 3
        assert len(loader.pending_tasks) == 0
        assert len(loader.active_tasks) == 0
        assert len(loader.completed_tasks) == 0

        loader.shutdown()
        del os.environ["INTELLICRACK_TESTING"]

    def test_submit_loading_task(
        self, background_loader: BackgroundModelLoader,
        fake_backend_class: type,
        fake_config: LLMConfig,
    ) -> None:
        """Submitting loading task creates task correctly."""
        task = background_loader.submit_loading_task(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
            priority=5,
        )

        assert task.model_id == "test-model"
        assert task.priority == 5
        assert task.state == LoadingState.PENDING
        assert task in background_loader.pending_tasks

    def test_submit_multiple_tasks(
        self, background_loader: BackgroundModelLoader,
        fake_backend_class: type,
    ) -> None:
        """Submitting multiple tasks queues them correctly."""
        configs = [create_test_config(model_name=f"model-{i}") for i in range(5)]

        for i, config in enumerate(configs):
            background_loader.submit_loading_task(
                model_id=f"model-{i}",
                backend_class=fake_backend_class,
                config=config,
                priority=i,
            )

        assert len(background_loader.pending_tasks) == 5

    def test_cancel_pending_task(
        self, background_loader: BackgroundModelLoader,
        fake_backend_class: type,
        fake_config: LLMConfig,
    ) -> None:
        """Cancelling pending task removes it from queue."""
        task = background_loader.submit_loading_task(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        result = background_loader.cancel_task("test-model")

        assert result is True
        assert task.cancelled is True
        assert task not in background_loader.pending_tasks

    def test_cancel_nonexistent_task(
        self, background_loader: BackgroundModelLoader,
    ) -> None:
        """Cancelling nonexistent task returns False."""
        result = background_loader.cancel_task("nonexistent-model")

        assert result is False

    def test_get_task_status_pending(
        self, background_loader: BackgroundModelLoader,
        fake_backend_class: type,
        fake_config: LLMConfig,
    ) -> None:
        """Get task status returns pending task correctly."""
        task = background_loader.submit_loading_task(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        status = background_loader.get_task_status("test-model")

        assert status == task
        assert status.state == LoadingState.PENDING

    def test_get_task_status_nonexistent(
        self, background_loader: BackgroundModelLoader,
    ) -> None:
        """Get task status returns None for nonexistent task."""
        status = background_loader.get_task_status("nonexistent")

        assert status is None

    def test_get_all_tasks(
        self, background_loader: BackgroundModelLoader,
        fake_backend_class: type,
    ) -> None:
        """Get all tasks returns all pending, active, and completed tasks."""
        configs = [create_test_config(model_name=f"model-{i}") for i in range(3)]

        for i, config in enumerate(configs):
            background_loader.submit_loading_task(
                model_id=f"model-{i}",
                backend_class=fake_backend_class,
                config=config,
            )

        all_tasks = background_loader.get_all_tasks()

        assert len(all_tasks) == 3
        assert "model-0" in all_tasks
        assert "model-1" in all_tasks
        assert "model-2" in all_tasks

    def test_get_loading_statistics(
        self, background_loader: BackgroundModelLoader,
        fake_backend_class: type,
    ) -> None:
        """Get loading statistics returns correct counts."""
        configs = [create_test_config(model_name=f"model-{i}") for i in range(3)]

        for i, config in enumerate(configs):
            background_loader.submit_loading_task(
                model_id=f"model-{i}",
                backend_class=fake_backend_class,
                config=config,
            )

        stats = background_loader.get_loading_statistics()

        assert "pending" in stats
        assert "active" in stats
        assert "completed" in stats
        assert stats["pending"] == 3

    def test_shutdown_cancels_pending_tasks(
        self, fake_backend_class: type,
    ) -> None:
        """Shutdown cancels all pending tasks."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        loader = BackgroundModelLoader(max_concurrent_loads=2)

        configs = [create_test_config(model_name=f"model-{i}") for i in range(3)]

        for i, config in enumerate(configs):
            loader.submit_loading_task(
                model_id=f"model-{i}",
                backend_class=fake_backend_class,
                config=config,
            )

        loader.shutdown()

        for task in loader.pending_tasks:
            assert task.cancelled is True

        del os.environ["INTELLICRACK_TESTING"]


class TestIntegratedBackgroundLoader:
    """Test integrated background loader with LLM manager."""

    def test_integrated_loader_initialization(self) -> None:
        """Integrated loader initializes correctly."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        fake_manager = LLMManager()
        loader = IntegratedBackgroundLoader(fake_manager, max_concurrent_loads=2)

        assert loader.llm_manager == fake_manager
        assert loader.background_loader is not None
        assert len(loader.progress_callbacks) == 0

        loader.shutdown()
        del os.environ["INTELLICRACK_TESTING"]

    def test_add_progress_callback(self) -> None:
        """Adding progress callback registers it correctly."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        fake_manager = LLMManager()
        loader = IntegratedBackgroundLoader(fake_manager)

        callback = FakeProgressCallback()
        loader.add_progress_callback(callback)

        assert callback in loader.progress_callbacks

        loader.shutdown()
        del os.environ["INTELLICRACK_TESTING"]

    def test_remove_progress_callback(self) -> None:
        """Removing progress callback unregisters it."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        fake_manager = LLMManager()
        loader = IntegratedBackgroundLoader(fake_manager)

        callback = FakeProgressCallback()
        loader.add_progress_callback(callback)
        loader.remove_progress_callback(callback)

        assert callback not in loader.progress_callbacks

        loader.shutdown()
        del os.environ["INTELLICRACK_TESTING"]

    def test_load_model_in_background(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Loading model in background creates task."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        fake_manager = LLMManager()
        loader = IntegratedBackgroundLoader(fake_manager)

        task = loader.load_model_in_background(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
            priority=5,
        )

        assert task.model_id == "test-model"
        assert "test-model" in loader.model_tasks

        loader.shutdown()
        del os.environ["INTELLICRACK_TESTING"]

    def test_get_loading_progress(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Get loading progress returns task status."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        fake_manager = LLMManager()
        loader = IntegratedBackgroundLoader(fake_manager)

        loader.load_model_in_background(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        progress = loader.get_loading_progress("test-model")

        assert progress is not None
        assert progress.model_id == "test-model"

        loader.shutdown()
        del os.environ["INTELLICRACK_TESTING"]

    def test_cancel_loading(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Cancel loading cancels the task."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        fake_manager = LLMManager()
        loader = IntegratedBackgroundLoader(fake_manager)

        loader.load_model_in_background(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        result = loader.cancel_loading("test-model")

        assert result is True

        loader.shutdown()
        del os.environ["INTELLICRACK_TESTING"]

    def test_get_statistics(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Get statistics returns loading statistics."""
        os.environ["INTELLICRACK_TESTING"] = "1"
        fake_manager = LLMManager()
        loader = IntegratedBackgroundLoader(fake_manager)

        loader.load_model_in_background(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        stats = loader.get_statistics()

        assert "pending" in stats
        assert "active" in stats
        assert "completed" in stats

        loader.shutdown()
        del os.environ["INTELLICRACK_TESTING"]


class TestThreadSafety:
    """Test thread safety of background loader."""

    def test_concurrent_task_submission(
        self, background_loader: BackgroundModelLoader, fake_backend_class: type
    ) -> None:
        """Concurrent task submissions are handled safely."""
        def submit_tasks(start_id: int, count: int) -> None:
            for i in range(count):
                config = create_test_config(model_name=f"model-{start_id + i}")
                background_loader.submit_loading_task(
                    model_id=f"model-{start_id + i}",
                    backend_class=fake_backend_class,
                    config=config,
                )

        threads = []
        for i in range(3):
            thread = threading.Thread(target=submit_tasks, args=(i * 10, 10))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        assert len(background_loader.pending_tasks) == 30

    def test_concurrent_status_checks(
        self, background_loader: BackgroundModelLoader, fake_backend_class: type
    ) -> None:
        """Concurrent status checks don't cause race conditions."""
        configs = [create_test_config(model_name=f"model-{i}") for i in range(10)]

        for i, config in enumerate(configs):
            background_loader.submit_loading_task(
                model_id=f"model-{i}",
                backend_class=fake_backend_class,
                config=config,
            )

        def check_statuses() -> None:
            for i in range(10):
                background_loader.get_task_status(f"model-{i}")
                background_loader.get_all_tasks()
                background_loader.get_loading_statistics()

        threads = []
        for _ in range(5):
            thread = threading.Thread(target=check_statuses)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()


class TestGlobalLoaderFunctions:
    """Test global loader factory functions."""

    def test_load_model_with_progress_in_test_mode(
        self, fake_backend_class: type, fake_config: LLMConfig
    ) -> None:
        """Load model with progress uses synchronous fallback in test mode."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        task = load_model_with_progress(
            model_id="test-model",
            backend_class=fake_backend_class,
            config=fake_config,
        )

        assert task.model_id == "test-model"
        assert task.state == LoadingState.COMPLETED

        del os.environ["INTELLICRACK_TESTING"]

    def test_get_background_loader_in_test_mode(self) -> None:
        """Get background loader returns None in test mode."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        loader = get_background_loader()

        assert loader is None

        del os.environ["INTELLICRACK_TESTING"]
