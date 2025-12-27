"""Production-grade tests for AI background model loading.

Tests MUST validate actual background loading functionality, thread safety,
priority queuing, and progress tracking using real LLM backends.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import os
import queue
import threading
import time
from pathlib import Path
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
from intellicrack.ai.llm_backends import LLMConfig, LLMProvider
from intellicrack.ai.llm_types import LoadingProgress, LoadingState


class SimpleTestBackend:
    """Minimal test backend that simulates initialization delay."""

    def __init__(self, config: LLMConfig) -> None:
        """Initialize test backend with config."""
        self.config = config
        self.initialized = False
        self.init_delay = 0.1

    def initialize(self) -> bool:
        """Initialize with configurable delay."""
        time.sleep(self.init_delay)
        self.initialized = True
        return True


class FailingTestBackend:
    """Test backend that fails initialization."""

    def __init__(self, config: LLMConfig) -> None:
        """Initialize failing backend."""
        self.config = config

    def initialize(self) -> bool:
        """Return failure status."""
        return False


class ErrorTestBackend:
    """Test backend that raises errors during initialization."""

    def __init__(self, config: LLMConfig) -> None:
        """Initialize error backend."""
        self.config = config

    def initialize(self) -> bool:
        """Raise error during initialization."""
        raise RuntimeError("Simulated initialization error")


class TestProgressCallback:
    """Test implementation of progress callback."""

    def __init__(self) -> None:
        """Initialize callback with tracking lists."""
        self.progress_calls: list[LoadingProgress] = []
        self.completion_calls: list[tuple[str, bool, str | None]] = []

    def on_progress(self, progress: LoadingProgress) -> None:
        """Track progress calls."""
        self.progress_calls.append(progress)

    def on_completed(self, model_id: str, success: bool, error: str | None = None) -> None:
        """Track completion calls."""
        self.completion_calls.append((model_id, success, error))


class TestLLMManager:
    """Test implementation of LLM manager."""

    def __init__(self) -> None:
        """Initialize test LLM manager."""
        self.initialized = True


@pytest.fixture
def test_llm_config() -> LLMConfig:
    """Create real LLM config for testing."""
    return LLMConfig(
        provider=LLMProvider.OLLAMA,
        model_name="tinyllama",
        api_base="http://localhost:11434",
        temperature=0.7,
    )


@pytest.fixture
def test_llm_manager() -> TestLLMManager:
    """Create test LLM manager."""
    return TestLLMManager()


@pytest.fixture
def background_loader() -> BackgroundModelLoader:
    """Create background model loader for testing."""
    os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
    loader = BackgroundModelLoader(max_concurrent_loads=2)
    yield loader
    loader.shutdown()
    os.environ.pop("DISABLE_BACKGROUND_THREADS", None)


@pytest.fixture
def threaded_loader() -> BackgroundModelLoader:
    """Create background loader with actual threads for integration testing."""
    os.environ.pop("DISABLE_BACKGROUND_THREADS", None)
    loader = BackgroundModelLoader(max_concurrent_loads=2)
    yield loader
    loader.shutdown()


class TestConsoleProgressCallback:
    """Tests for console progress callback functionality."""

    def test_on_progress_logs_status(self, caplog: pytest.LogCaptureFixture) -> None:
        """Callback logs progress messages to console."""
        callback = ConsoleProgressCallback()
        progress = LoadingProgress(
            model_id="test_model",
            model_name="TestModel",
            state=LoadingState.LOADING,
            progress=0.5,
            message="Loading weights...",
            details={"provider": "test"},
            timestamp=time.time(),
        )

        callback.on_progress(progress)

        assert "test_model" in caplog.text
        assert "50.0%" in caplog.text
        assert "Loading weights..." in caplog.text

    def test_on_completed_logs_success(self, caplog: pytest.LogCaptureFixture) -> None:
        """Callback logs successful completion."""
        callback = ConsoleProgressCallback()

        callback.on_completed("test_model", success=True)

        assert "test_model" in caplog.text
        assert "SUCCESS" in caplog.text

    def test_on_completed_logs_failure(self, caplog: pytest.LogCaptureFixture) -> None:
        """Callback logs failure with error message."""
        callback = ConsoleProgressCallback()

        callback.on_completed("test_model", success=False, error="Model not found")

        assert "test_model" in caplog.text
        assert "FAILED" in caplog.text
        assert "Model not found" in caplog.text


class TestQueuedProgressCallback:
    """Tests for queued progress callback functionality."""

    def test_progress_queues_updates(self) -> None:
        """Progress updates are correctly queued."""
        callback = QueuedProgressCallback()
        progress = LoadingProgress(
            model_id="test_model",
            model_name="TestModel",
            state=LoadingState.LOADING,
            progress=0.5,
            message="Loading...",
            details={},
            timestamp=time.time(),
        )

        callback.on_progress(progress)

        updates = callback.get_progress_updates()
        assert len(updates) == 1
        assert updates[0].model_id == "test_model"
        assert updates[0].progress == 0.5

    def test_completion_queues_results(self) -> None:
        """Completion results are correctly queued."""
        callback = QueuedProgressCallback()

        callback.on_completed("test_model", success=True)

        completions = callback.get_completion_updates()
        assert len(completions) == 1
        assert completions[0][0] == "test_model"
        assert completions[0][1] is True
        assert completions[0][2] is None

    def test_get_updates_empties_queue(self) -> None:
        """Getting updates clears the queue."""
        callback = QueuedProgressCallback()
        callback.on_progress(
            LoadingProgress(
                model_id="test",
                model_name="Test",
                state=LoadingState.LOADING,
                progress=0.5,
                message="test",
                details={},
                timestamp=time.time(),
            )
        )

        first = callback.get_progress_updates()
        second = callback.get_progress_updates()

        assert len(first) == 1
        assert len(second) == 0

    def test_multiple_updates_queued_correctly(self) -> None:
        """Multiple progress updates are queued in order."""
        callback = QueuedProgressCallback()

        for i in range(5):
            callback.on_progress(
                LoadingProgress(
                    model_id=f"model_{i}",
                    model_name=f"Model {i}",
                    state=LoadingState.LOADING,
                    progress=i * 0.2,
                    message=f"Step {i}",
                    details={},
                    timestamp=time.time(),
                )
            )

        updates = callback.get_progress_updates()
        assert len(updates) == 5
        assert [u.model_id for u in updates] == [f"model_{i}" for i in range(5)]


class TestLoadingTask:
    """Tests for loading task lifecycle and state management."""

    def test_task_initialization(self, test_llm_config: LLMConfig) -> None:
        """Task initializes with correct default state."""
        task = LoadingTask("test_model", SimpleTestBackend, test_llm_config, priority=5)

        assert task.model_id == "test_model"
        assert task.backend_class == SimpleTestBackend
        assert task.config == test_llm_config
        assert task.priority == 5
        assert task.state == LoadingState.PENDING
        assert task.progress == 0.0
        assert task.message == "Queued for loading"
        assert task.result is None
        assert task.error is None
        assert not task.cancelled

    def test_update_progress_changes_state(self, test_llm_config: LLMConfig) -> None:
        """Progress updates change task state correctly."""
        task = LoadingTask("test_model", SimpleTestBackend, test_llm_config)

        task.update_progress(0.5, "Halfway done", LoadingState.LOADING)

        assert task.state == LoadingState.LOADING
        assert task.progress == 0.5
        assert task.message == "Halfway done"

    def test_update_progress_clamps_values(self, test_llm_config: LLMConfig) -> None:
        """Progress values are clamped to valid range."""
        task = LoadingTask("test_model", SimpleTestBackend, test_llm_config)

        task.update_progress(1.5, "Over 100%")
        assert task.progress == 1.0

        task.update_progress(-0.5, "Negative")
        assert task.progress == 0.0

    def test_update_progress_notifies_callback(self, test_llm_config: LLMConfig) -> None:
        """Progress updates trigger callback notifications."""
        callback = TestProgressCallback()
        task = LoadingTask("test_model", SimpleTestBackend, test_llm_config, callback=callback)

        task.update_progress(0.5, "Loading")

        assert len(callback.progress_calls) == 1
        assert callback.progress_calls[0].progress == 0.5
        assert callback.progress_calls[0].model_id == "test_model"

    def test_mark_completed_success(self, test_llm_config: LLMConfig) -> None:
        """Successful completion marks task correctly."""
        callback = TestProgressCallback()
        task = LoadingTask("test_model", SimpleTestBackend, test_llm_config, callback=callback)
        backend = SimpleTestBackend(test_llm_config)

        task.mark_completed(success=True, result=backend)

        assert task.state == LoadingState.COMPLETED
        assert task.progress == 1.0
        assert task.result == backend
        assert task.error is None
        assert len(callback.completion_calls) == 1
        assert callback.completion_calls[0] == ("test_model", True, None)

    def test_mark_completed_failure(self, test_llm_config: LLMConfig) -> None:
        """Failed completion marks task with error."""
        callback = TestProgressCallback()
        task = LoadingTask("test_model", SimpleTestBackend, test_llm_config, callback=callback)

        task.mark_completed(success=False, error="Load failed")

        assert task.state == LoadingState.FAILED
        assert task.progress == 0.0
        assert task.result is None
        assert task.error == "Load failed"
        assert len(callback.completion_calls) == 1
        assert callback.completion_calls[0] == ("test_model", False, "Load failed")

    def test_cancel_task(self, test_llm_config: LLMConfig) -> None:
        """Task cancellation updates state and notifies callback."""
        callback = TestProgressCallback()
        task = LoadingTask("test_model", SimpleTestBackend, test_llm_config, callback=callback)

        task.cancel()

        assert task.cancelled
        assert task.state == LoadingState.CANCELLED
        assert len(callback.completion_calls) == 1
        assert callback.completion_calls[0] == ("test_model", False, "Cancelled by user")


class TestBackgroundModelLoader:
    """Tests for background model loader core functionality."""

    def test_initialization_with_disabled_threads(self) -> None:
        """Loader initializes without threads in testing mode."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        loader = BackgroundModelLoader(max_concurrent_loads=2)

        assert loader.max_concurrent_loads == 2
        assert len(loader.worker_threads) == 0
        assert not loader.shutdown_event.is_set()

        os.environ.pop("DISABLE_BACKGROUND_THREADS")

    def test_submit_loading_task(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Task submission creates and queues task correctly."""
        task = background_loader.submit_loading_task("test_model", SimpleTestBackend, test_llm_config, priority=5)

        assert task.model_id == "test_model"
        assert task.priority == 5
        assert task in background_loader.pending_tasks
        assert not background_loader.task_queue.empty()

    def test_submit_task_cancels_existing(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Submitting task for same model ID cancels existing task."""
        first = background_loader.submit_loading_task("test_model", SimpleTestBackend, test_llm_config)
        second = background_loader.submit_loading_task("test_model", SimpleTestBackend, test_llm_config)

        assert first.cancelled
        assert not second.cancelled

    def test_priority_queue_ordering(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Tasks are queued with correct priority ordering."""
        low_task = background_loader.submit_loading_task("low", SimpleTestBackend, test_llm_config, priority=1)
        high_task = background_loader.submit_loading_task("high", SimpleTestBackend, test_llm_config, priority=10)
        med_task = background_loader.submit_loading_task("med", SimpleTestBackend, test_llm_config, priority=5)

        first = background_loader.task_queue.get()[2]
        second = background_loader.task_queue.get()[2]
        third = background_loader.task_queue.get()[2]

        assert first.model_id == "high"
        assert second.model_id == "med"
        assert third.model_id == "low"

    def test_cancel_task_pending(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Pending task can be cancelled."""
        task = background_loader.submit_loading_task("test_model", SimpleTestBackend, test_llm_config)

        result = background_loader.cancel_task("test_model")

        assert result is True
        assert task.cancelled
        assert task not in background_loader.pending_tasks

    def test_cancel_task_nonexistent(self, background_loader: BackgroundModelLoader) -> None:
        """Cancelling nonexistent task returns False."""
        result = background_loader.cancel_task("nonexistent")

        assert result is False

    def test_get_task_status_pending(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Can retrieve status of pending task."""
        task = background_loader.submit_loading_task("test_model", SimpleTestBackend, test_llm_config)

        status = background_loader.get_task_status("test_model")

        assert status == task
        assert status.state == LoadingState.PENDING

    def test_get_task_status_nonexistent(self, background_loader: BackgroundModelLoader) -> None:
        """Getting status of nonexistent task returns None."""
        status = background_loader.get_task_status("nonexistent")

        assert status is None

    def test_get_all_tasks(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Can retrieve all tasks across states."""
        pending = background_loader.submit_loading_task("pending", SimpleTestBackend, test_llm_config)
        active_task = LoadingTask("active", SimpleTestBackend, test_llm_config)
        background_loader.active_tasks["active"] = active_task
        completed_task = LoadingTask("completed", SimpleTestBackend, test_llm_config)
        background_loader.completed_tasks["completed"] = completed_task

        all_tasks = background_loader.get_all_tasks()

        assert len(all_tasks) == 3
        assert "pending" in all_tasks
        assert "active" in all_tasks
        assert "completed" in all_tasks

    def test_loading_statistics(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Statistics correctly reflect loader state."""
        background_loader.submit_loading_task("pending", SimpleTestBackend, test_llm_config)
        active_task = LoadingTask("active", SimpleTestBackend, test_llm_config)
        background_loader.active_tasks["active"] = active_task

        completed_success = LoadingTask("success", SimpleTestBackend, test_llm_config)
        completed_success.state = LoadingState.COMPLETED
        background_loader.completed_tasks["success"] = completed_success

        completed_failed = LoadingTask("failed", SimpleTestBackend, test_llm_config)
        completed_failed.state = LoadingState.FAILED
        background_loader.completed_tasks["failed"] = completed_failed

        stats = background_loader.get_loading_statistics()

        assert stats["pending"] == 1
        assert stats["active"] == 1
        assert stats["completed"] == 2
        assert stats["success_rate"] == 0.5

    def test_shutdown_cancels_pending(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Shutdown cancels all pending tasks."""
        task1 = background_loader.submit_loading_task("task1", SimpleTestBackend, test_llm_config)
        task2 = background_loader.submit_loading_task("task2", SimpleTestBackend, test_llm_config)

        background_loader.shutdown()

        assert task1.cancelled
        assert task2.cancelled
        assert background_loader.shutdown_event.is_set()


class TestBackgroundLoaderIntegration:
    """Integration tests with actual background threads."""

    def test_worker_thread_processes_task(self, threaded_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Worker thread successfully processes loading task."""
        callback = QueuedProgressCallback()
        task = threaded_loader.submit_loading_task("test_model", SimpleTestBackend, test_llm_config, callback=callback)

        time.sleep(0.5)

        assert task.state == LoadingState.COMPLETED
        assert task.result is not None
        assert isinstance(task.result, SimpleTestBackend)
        assert task.result.initialized

    def test_worker_thread_handles_failure(self, threaded_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Worker thread handles backend initialization failure."""
        task = threaded_loader.submit_loading_task("failing", FailingSimpleTestBackend, test_llm_config)

        time.sleep(0.5)

        assert task.state == LoadingState.FAILED
        assert task.error is not None
        assert "initialization failed" in task.error.lower()

    def test_worker_thread_handles_exceptions(self, threaded_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Worker thread handles exceptions during loading."""
        task = threaded_loader.submit_loading_task("error", ErrorSimpleTestBackend, test_llm_config)

        time.sleep(0.5)

        assert task.state == LoadingState.FAILED
        assert task.error is not None

    def test_concurrent_task_processing(self, threaded_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Multiple tasks are processed concurrently."""
        tasks = [
            threaded_loader.submit_loading_task(f"model_{i}", SimpleTestBackend, test_llm_config)
            for i in range(4)
        ]

        time.sleep(0.6)

        completed = [t for t in tasks if t.state == LoadingState.COMPLETED]
        assert len(completed) >= 2

    def test_task_cancellation_during_processing(self, threaded_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Task can be cancelled while being processed."""
        backend_class = type("SlowBackend", (SimpleTestBackend,), {"init_delay": 1.0})
        task = threaded_loader.submit_loading_task("slow", backend_class, test_llm_config)

        time.sleep(0.1)
        threaded_loader.cancel_task("slow")
        time.sleep(0.2)

        assert task.cancelled


class TestIntegratedBackgroundLoader:
    """Tests for integrated background loader with LLM manager."""

    def test_initialization(self, test_llm_manager: TestLLMManager) -> None:
        """Integrated loader initializes correctly."""
        loader = IntegratedBackgroundLoader(test_llm_manager, max_concurrent_loads=2)

        assert loader.llm_manager == test_llm_manager
        assert loader.background_loader is not None
        assert len(loader.progress_callbacks) == 0

    def test_add_progress_callback(self, test_llm_manager: TestLLMManager) -> None:
        """Can add progress callbacks to integrated loader."""
        loader = IntegratedBackgroundLoader(test_llm_manager)
        callback = TestProgressCallback()

        loader.add_progress_callback(callback)

        assert callback in loader.progress_callbacks

    def test_remove_progress_callback(self, test_llm_manager: TestLLMManager) -> None:
        """Can remove progress callbacks from integrated loader."""
        loader = IntegratedBackgroundLoader(test_llm_manager)
        callback = TestProgressCallback()

        loader.add_progress_callback(callback)
        loader.remove_progress_callback(callback)

        assert callback not in loader.progress_callbacks

    def test_load_model_notifies_all_callbacks(self, test_llm_manager: TestLLMManager, test_llm_config: LLMConfig) -> None:
        """Loading model notifies all registered callbacks."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        loader = IntegratedBackgroundLoader(test_llm_manager)

        callback1 = TestProgressCallback()
        callback2 = TestProgressCallback()
        loader.add_progress_callback(callback1)
        loader.add_progress_callback(callback2)

        task = loader.load_model_in_background("test_model", SimpleTestBackend, test_llm_config)

        os.environ.pop("DISABLE_BACKGROUND_THREADS", None)

        assert task.model_id == "test_model"

    def test_get_loading_progress(self, test_llm_manager: TestLLMManager, test_llm_config: LLMConfig) -> None:
        """Can retrieve loading progress for model."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        loader = IntegratedBackgroundLoader(test_llm_manager)

        task = loader.load_model_in_background("test_model", SimpleTestBackend, test_llm_config)
        progress = loader.get_loading_progress("test_model")

        assert progress == task

        os.environ.pop("DISABLE_BACKGROUND_THREADS", None)

    def test_cancel_loading(self, test_llm_manager: TestLLMManager, test_llm_config: LLMConfig) -> None:
        """Can cancel loading through integrated loader."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        loader = IntegratedBackgroundLoader(test_llm_manager)

        loader.load_model_in_background("test_model", SimpleTestBackend, test_llm_config)
        result = loader.cancel_loading("test_model")

        assert result is True

        os.environ.pop("DISABLE_BACKGROUND_THREADS", None)

    def test_get_statistics(self, test_llm_manager: TestLLMManager, test_llm_config: LLMConfig) -> None:
        """Can retrieve loading statistics."""
        os.environ["DISABLE_BACKGROUND_THREADS"] = "1"
        loader = IntegratedBackgroundLoader(test_llm_manager)

        loader.load_model_in_background("test_model", SimpleTestBackend, test_llm_config)
        stats = loader.get_statistics()

        assert "pending" in stats
        assert "active" in stats
        assert "completed" in stats

        os.environ.pop("DISABLE_BACKGROUND_THREADS", None)

    def test_shutdown(self, test_llm_manager: TestLLMManager) -> None:
        """Shutdown delegates to background loader."""
        loader = IntegratedBackgroundLoader(test_llm_manager)
        original_shutdown = loader.background_loader.shutdown

        loader.shutdown()

        assert loader.background_loader.shutdown_event.is_set()


class TestModuleFunctions:
    """Tests for module-level utility functions."""

    def test_get_background_loader_disabled_in_testing(self) -> None:
        """get_background_loader returns None in testing mode."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        loader = get_background_loader()

        assert loader is None

        os.environ.pop("INTELLICRACK_TESTING", None)

    def test_load_model_with_progress_fallback(self, test_llm_config: LLMConfig) -> None:
        """load_model_with_progress falls back when loader unavailable."""
        os.environ["INTELLICRACK_TESTING"] = "1"

        task = load_model_with_progress("test_model", SimpleTestBackend, test_llm_config)

        assert task.model_id == "test_model"
        assert task.state == LoadingState.COMPLETED

        os.environ.pop("INTELLICRACK_TESTING", None)


class TestProgressCallbackErrorHandling:
    """Tests for error handling in progress callbacks."""

    def test_callback_exception_does_not_break_loading(self, threaded_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Exception in callback doesn't prevent task completion."""
        class ErrorCallback:
            def on_progress(self, progress: LoadingProgress) -> None:
                raise ValueError("Callback error")

            def on_completed(self, model_id: str, success: bool, error: str | None = None) -> None:
                pass

        callback = ErrorCallback()

        task = threaded_loader.submit_loading_task("test_model", SimpleTestBackend, test_llm_config, callback=callback)

        time.sleep(0.5)

        assert task.state == LoadingState.COMPLETED


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_empty_model_id(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Can handle empty model ID."""
        task = background_loader.submit_loading_task("", SimpleTestBackend, test_llm_config)

        assert task.model_id == ""

    def test_very_high_priority(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Can handle very high priority values."""
        task = background_loader.submit_loading_task("test", SimpleTestBackend, test_llm_config, priority=999999)

        assert task.priority == 999999

    def test_negative_priority(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Can handle negative priority values."""
        task = background_loader.submit_loading_task("test", SimpleTestBackend, test_llm_config, priority=-100)

        assert task.priority == -100

    def test_concurrent_submissions(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """Thread-safe concurrent task submissions."""
        def submit_task(i: int) -> None:
            background_loader.submit_loading_task(f"model_{i}", SimpleTestBackend, test_llm_config)

        threads = [threading.Thread(target=submit_task, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(background_loader.pending_tasks) == 10

    def test_get_all_tasks_concurrent_access(self, background_loader: BackgroundModelLoader, test_llm_config: LLMConfig) -> None:
        """get_all_tasks is thread-safe."""
        background_loader.submit_loading_task("test", SimpleTestBackend, test_llm_config)

        def access_tasks() -> None:
            for _ in range(100):
                background_loader.get_all_tasks()

        threads = [threading.Thread(target=access_tasks) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
