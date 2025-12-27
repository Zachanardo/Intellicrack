"""Background Model Loading with Progress for Intellicrack.

This module provides background loading capabilities for AI models with
real-time progress updates and user feedback.

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
import queue
import threading
import time
from typing import TYPE_CHECKING, Any, Optional

from .llm_types import LoadingProgress, LoadingState, ProgressCallback


if TYPE_CHECKING:
    from .llm_backends import LLMBackend, LLMConfig, LLMManager

logger = logging.getLogger(__name__)


class ConsoleProgressCallback(ProgressCallback):
    """Console-based progress callback for debugging."""

    def __init__(self) -> None:
        """Initialize the console progress callback."""
        self._logger = logging.getLogger(f"{__name__}.ConsoleProgressCallback")

    def on_progress(self, progress: LoadingProgress) -> None:
        """Log progress to console.

        Args:
            progress: Progress information to log.
        """
        self._logger.info("[%s] %s: %.1f%% - %s", progress.model_id, progress.state.value, progress.progress * 100, progress.message)

    def on_completed(self, model_id: str, success: bool, error: str | None = None) -> None:
        """Log completion status.

        Args:
            model_id: Unique identifier for the model.
            success: Whether the operation was successful.
            error: Error message if the operation failed.
        """
        status = "SUCCESS" if success else f"FAILED: {error}"
        self._logger.info("[%s] Loading completed: %s", model_id, status)


class QueuedProgressCallback(ProgressCallback):
    """Queue-based progress callback for GUI integration."""

    def __init__(self) -> None:
        """Initialize the queue-based progress callback.

        Sets up queues for progress updates and completion notifications
        for thread-safe communication with GUI components.
        """
        self.progress_queue: queue.Queue[LoadingProgress] = queue.Queue()
        self.completion_queue: queue.Queue[tuple[str, bool, str | None]] = queue.Queue()
        self.logger = logging.getLogger(f"{__name__}.QueuedProgressCallback")

    def on_progress(self, progress: LoadingProgress) -> None:
        """Add progress to queue.

        Args:
            progress: Progress information to queue.
        """
        self.progress_queue.put(progress)

    def on_completed(self, model_id: str, success: bool, error: str | None = None) -> None:
        """Add completion to queue.

        Args:
            model_id: Unique identifier for the model.
            success: Whether the operation was successful.
            error: Error message if the operation failed.
        """
        self.completion_queue.put((model_id, success, error))

    def get_progress_updates(self) -> list[LoadingProgress]:
        """Get all pending progress updates.

        Returns:
            A list of all pending LoadingProgress updates from the queue.
        """
        updates = []
        try:
            while True:
                updates.append(self.progress_queue.get_nowait())
        except queue.Empty:
            logger.debug("Retrieved %d progress updates from queue", len(updates))
        return updates

    def get_completion_updates(self) -> list[tuple[str, bool, str | None]]:
        """Get all pending completion updates.

        Returns:
            A list of tuples containing (model_id, success, error) for each completion.
        """
        updates: list[tuple[str, bool, str | None]] = []
        try:
            while True:
                updates.append(self.completion_queue.get_nowait())
        except queue.Empty:
            pass
        return updates


class LoadingTask:
    """A single model loading task."""

    def __init__(
        self,
        model_id: str,
        backend_class: type,
        config: "LLMConfig",
        priority: int = 0,
        callback: ProgressCallback | None = None,
    ) -> None:
        """Initialize a model loading task.

        Args:
            model_id: Unique identifier for the model
            backend_class: Backend class to instantiate for this model
            config: Configuration for the LLM backend
            priority: Loading priority (higher numbers loaded first)
            callback: Optional progress callback for status updates

        """
        self.model_id = model_id
        self.backend_class = backend_class
        self.config = config
        self.priority = priority
        self.callback = callback
        self.state = LoadingState.PENDING
        self.progress = 0.0
        self.message = "Queued for loading"
        self.start_time: float | None = None
        self.end_time: float | None = None
        self.result: LLMBackend | None = None
        self.error: str | None = None
        self.cancelled = False

    def update_progress(self, progress: float, message: str, state: LoadingState | None = None) -> None:
        """Update task progress.

        Args:
            progress: Progress value between 0.0 and 1.0.
            message: Status message describing the current operation.
            state: Optional LoadingState to update. If not provided, state remains unchanged.
        """
        if state:
            self.state = state
        self.progress = min(1.0, max(0.0, progress))
        self.message = message

        if self.callback:
            model_name = self.config.model_name if self.config.model_name is not None else "Unknown"
            progress_info = LoadingProgress(
                model_id=self.model_id,
                model_name=model_name,
                state=self.state,
                progress=self.progress,
                message=message,
                details={
                    "provider": self.config.provider.value,
                    "priority": self.priority,
                    "elapsed_time": time.time() - self.start_time if self.start_time else 0,
                },
                timestamp=time.time(),
            )
            self.callback.on_progress(progress_info)

    def mark_completed(self, success: bool, result: Optional["LLMBackend"] = None, error: str | None = None) -> None:
        """Mark task as completed.

        Args:
            success: Whether the task completed successfully.
            result: The loaded LLMBackend instance if successful.
            error: Error message if the task failed.
        """
        self.end_time = time.time()
        self.result = result
        self.error = error
        self.state = LoadingState.COMPLETED if success else LoadingState.FAILED
        self.progress = 1.0 if success else 0.0
        self.message = "Loading completed" if success else f"Loading failed: {error}"

        if self.callback:
            self.callback.on_completed(self.model_id, success, error)

    def cancel(self) -> None:
        """Cancel the task.

        Sets the task state to CANCELLED and notifies the callback if present.
        """
        self.cancelled = True
        self.state = LoadingState.CANCELLED
        self.message = "Loading cancelled"

        if self.callback:
            self.callback.on_completed(self.model_id, False, "Cancelled by user")


class BackgroundModelLoader:
    """Background model loader with progress tracking.

    Loads models in background threads with priority queuing and progress updates.
    """

    def __init__(self, max_concurrent_loads: int = 2) -> None:
        """Initialize the background model loader.

        Args:
            max_concurrent_loads: Maximum number of models to load simultaneously

        """
        self.logger = logging.getLogger(f"{__name__}.BackgroundModelLoader")
        self.max_concurrent_loads = max_concurrent_loads
        self.pending_tasks: list[LoadingTask] = []
        self.active_tasks: dict[str, LoadingTask] = {}
        self.completed_tasks: dict[str, LoadingTask] = {}
        self.worker_threads: list[threading.Thread] = []
        self.task_queue: queue.PriorityQueue[tuple[int, float, LoadingTask]] = queue.PriorityQueue()
        self.shutdown_event = threading.Event()
        self.lock = threading.RLock()

        # Start worker threads (skip during testing)
        if not (os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS")):
            for i in range(max_concurrent_loads):
                thread = threading.Thread(target=self._worker_thread, name=f"ModelLoader-{i}", daemon=True)
                thread.start()
                self.worker_threads.append(thread)
            logger.info("Background model loader started with %d workers", max_concurrent_loads)
        else:
            logger.info("Skipping background model loader worker threads (testing mode)")

    def submit_loading_task(
        self,
        model_id: str,
        backend_class: type,
        config: "LLMConfig",
        priority: int = 0,
        callback: ProgressCallback | None = None,
    ) -> LoadingTask:
        """Submit a model loading task.

        Args:
            model_id: Unique identifier for the model.
            backend_class: Backend class to instantiate for loading.
            config: Configuration for the LLM backend.
            priority: Loading priority (higher numbers loaded first).
            callback: Optional progress callback for status updates.

        Returns:
            The created LoadingTask instance.
        """
        with self.lock:
            # Cancel any existing task for this model
            if model_id in self.active_tasks:
                self.cancel_task(model_id)

            task = LoadingTask(model_id, backend_class, config, priority, callback)
            self.pending_tasks.append(task)

            # Add to priority queue (negative priority for max-heap behavior)
            self.task_queue.put((-priority, time.time(), task))

            logger.info("Submitted loading task for %s (priority: %d)", model_id, priority)
            return task

    def cancel_task(self, model_id: str) -> bool:
        """Cancel a pending or active task.

        Args:
            model_id: Unique identifier for the model task to cancel.

        Returns:
            True if a task was found and cancelled, False otherwise.
        """
        with self.lock:
            # Check active tasks
            if model_id in self.active_tasks:
                task = self.active_tasks[model_id]
                task.cancel()
                return True

            # Check pending tasks
            for task in self.pending_tasks:
                if task.model_id == model_id:
                    task.cancel()
                    self.pending_tasks.remove(task)
                    return True

            return False

    def get_task_status(self, model_id: str) -> LoadingTask | None:
        """Get the status of a loading task.

        Args:
            model_id: Unique identifier for the model task.

        Returns:
            The LoadingTask instance if found, None otherwise.
        """
        with self.lock:
            if model_id in self.active_tasks:
                return self.active_tasks[model_id]
            if model_id in self.completed_tasks:
                return self.completed_tasks[model_id]
            return next(
                (task for task in self.pending_tasks if task.model_id == model_id),
                None,
            )

    def get_all_tasks(self) -> dict[str, LoadingTask]:
        """Get all tasks (pending, active, and completed).

        Returns:
            Dictionary mapping model IDs to their LoadingTask instances.
        """
        with self.lock:
            all_tasks = {task.model_id: task for task in self.pending_tasks}
            # Add active tasks
            all_tasks |= self.active_tasks

            # Add completed tasks
            all_tasks.update(self.completed_tasks)

            return all_tasks

    def get_loading_statistics(self) -> dict[str, Any]:
        """Get loading statistics.

        Returns:
            Dictionary containing statistics about pending, active, and completed tasks,
            including success rate and worker thread information.
        """
        with self.lock:
            stats: dict[str, Any] = {
                "pending": len(self.pending_tasks),
                "active": len(self.active_tasks),
                "completed": len(self.completed_tasks),
                "total_workers": len(self.worker_threads),
                "active_workers": len(self.active_tasks),
            }

            if completed_tasks := list(self.completed_tasks.values()):
                successful = sum(task.state == LoadingState.COMPLETED for task in completed_tasks)
                stats["success_rate"] = float(successful) / float(len(completed_tasks))
            else:
                stats["success_rate"] = 0.0

            return stats

    def _worker_thread(self) -> None:
        """Worker thread for loading models.

        Processes tasks from the priority queue, manages task lifecycle transitions,
        and handles errors during model loading operations.
        """
        thread_name = threading.current_thread().name
        logger.info("Model loader worker %s started", thread_name)

        while not self.shutdown_event.is_set():
            try:
                # Get next task from queue (with timeout)
                try:
                    _, _, task = self.task_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                if task.cancelled:
                    continue

                # Move task to active
                with self.lock:
                    self.active_tasks[task.model_id] = task
                    if task in self.pending_tasks:
                        self.pending_tasks.remove(task)

                # Load the model
                self._load_model(task)

                # Move to completed
                with self.lock:
                    if task.model_id in self.active_tasks:
                        del self.active_tasks[task.model_id]
                    self.completed_tasks[task.model_id] = task

            except Exception as e:
                logger.exception("Error in worker thread %s: %s", thread_name, e)

    def _load_model(self, task: LoadingTask) -> None:
        """Load a model with progress tracking.

        Args:
            task: The LoadingTask to execute.

        Handles errors gracefully by marking the task as failed with an error message.
        """
        task.start_time = time.time()

        try:
            self._execute_load_stages(task)
        except Exception as e:
            if not task.cancelled:
                error_msg = str(e)
                task.mark_completed(False, error=error_msg)
                logger.exception("Error loading model %s: %s", task.model_id, e)

    def _execute_load_stages(self, task: LoadingTask) -> None:
        """Execute all loading stages with cancellation checks.

        Args:
            task: The LoadingTask to execute stages for.

        Manages the complete loading pipeline including backend initialization,
        preparation, and model loading with regular cancellation checks.
        """
        cancelled = task.cancelled
        if cancelled:
            return

        task.update_progress(0.1, "Initializing backend...", LoadingState.INITIALIZING)

        cancelled = task.cancelled
        if cancelled:
            return

        backend: LLMBackend = task.backend_class(task.config)

        cancelled = task.cancelled
        if cancelled:
            return

        task.update_progress(0.3, "Preparing model...", LoadingState.DOWNLOADING)

        cancelled = task.cancelled
        if cancelled:
            return

        task.update_progress(0.5, "Loading model...", LoadingState.LOADING)

        cancelled = task.cancelled
        if cancelled:
            return

        success: bool = backend.initialize()

        cancelled = task.cancelled
        if cancelled:
            return

        self._finalize_load(task, success, backend)

    def _finalize_load(self, task: LoadingTask, success: bool, backend: "LLMBackend") -> None:
        """Finalize model loading after initialization.

        Args:
            task: The LoadingTask to finalize.
            success: Whether backend initialization was successful.
            backend: The LLMBackend instance that was loaded.

        Marks the task as completed with appropriate state based on success status.
        """
        if success:
            task.update_progress(1.0, "Model loaded successfully", LoadingState.COMPLETED)
            task.mark_completed(True, backend)
            logger.info("Successfully loaded model %s", task.model_id)
        else:
            task.mark_completed(False, error="Backend initialization failed")
            logger.error("Failed to initialize backend for %s", task.model_id)

    def shutdown(self) -> None:
        """Shutdown the background loader.

        Signals worker threads to stop, cancels all pending tasks, and waits
        for threads to complete with a timeout of 5 seconds per thread.
        """
        logger.info("Shutting down background model loader...")
        self.shutdown_event.set()

        # Cancel all pending tasks
        with self.lock:
            for task in self.pending_tasks:
                task.cancel()

        # Wait for worker threads to finish
        for thread in self.worker_threads:
            thread.join(timeout=5.0)

        logger.info("Background model loader shutdown complete")


class IntegratedBackgroundLoader:
    """Integration layer between background loader and LLM manager.

    Provides seamless integration with lazy loading and model management.
    """

    def __init__(self, llm_manager: "LLMManager", max_concurrent_loads: int = 2) -> None:
        """Initialize the integrated background loader.

        Args:
            llm_manager: LLM manager instance for model registration
            max_concurrent_loads: Maximum number of concurrent model loads

        """
        self.llm_manager = llm_manager
        self.background_loader = BackgroundModelLoader(max_concurrent_loads)
        self.progress_callbacks: list[ProgressCallback] = []
        self.model_tasks: dict[str, LoadingTask] = {}

    def add_progress_callback(self, callback: ProgressCallback) -> None:
        """Add a progress callback.

        Args:
            callback: Progress callback to add to the callback list.
        """
        self.progress_callbacks.append(callback)

    def remove_progress_callback(self, callback: ProgressCallback) -> None:
        """Remove a progress callback.

        Args:
            callback: Progress callback to remove from the callback list.
        """
        if callback in self.progress_callbacks:
            self.progress_callbacks.remove(callback)

    def load_model_in_background(self, model_id: str, backend_class: type, config: "LLMConfig", priority: int = 0) -> LoadingTask:
        """Load a model in the background with integrated callbacks.

        Args:
            model_id: Unique identifier for the model.
            backend_class: Backend class to instantiate for loading.
            config: Configuration for the LLM backend.
            priority: Loading priority (higher numbers loaded first).

        Returns:
            The created LoadingTask instance.
        """

        # Create a callback that notifies all registered callbacks
        class MultiCallback(ProgressCallback):
            def __init__(self, callbacks: list[ProgressCallback]) -> None:
                """Initialize multi-callback handler with list of callbacks.

                Args:
                    callbacks: List of ProgressCallback instances to aggregate.
                """
                self.callbacks = callbacks

            def on_progress(self, progress: LoadingProgress) -> None:
                """Notify all registered callbacks of progress.

                Args:
                    progress: Progress information to pass to callbacks.
                """
                for callback in self.callbacks:
                    try:
                        callback.on_progress(progress)
                    except Exception as e:
                        logger.warning("Error in progress callback: %s", e, exc_info=True)

            def on_completed(self, model_id: str, success: bool, error: str | None = None) -> None:
                """Notify all registered callbacks of completion.

                Args:
                    model_id: Unique identifier for the model.
                    success: Whether the operation was successful.
                    error: Error message if the operation failed.
                """
                for callback in self.callbacks:
                    try:
                        callback.on_completed(model_id, success, error)
                    except Exception as e:
                        logger.warning("Error in completion callback: %s", e, exc_info=True)

        multi_callback = MultiCallback(self.progress_callbacks)

        task = self.background_loader.submit_loading_task(
            model_id=model_id,
            backend_class=backend_class,
            config=config,
            priority=priority,
            callback=multi_callback,
        )

        self.model_tasks[model_id] = task
        return task

    def get_loading_progress(self, model_id: str) -> LoadingTask | None:
        """Get loading progress for a model.

        Args:
            model_id: Unique identifier for the model.

        Returns:
            The LoadingTask instance if found, None otherwise.
        """
        return self.background_loader.get_task_status(model_id)

    def cancel_loading(self, model_id: str) -> bool:
        """Cancel loading a model.

        Args:
            model_id: Unique identifier for the model task to cancel.

        Returns:
            True if a task was found and cancelled, False otherwise.
        """
        return self.background_loader.cancel_task(model_id)

    def get_all_loading_tasks(self) -> dict[str, LoadingTask]:
        """Get all loading tasks.

        Returns:
            Dictionary mapping model IDs to their LoadingTask instances.
        """
        return self.background_loader.get_all_tasks()

    def get_statistics(self) -> dict[str, Any]:
        """Get loading statistics.

        Returns:
            Dictionary containing statistics about pending, active, and completed tasks.
        """
        return self.background_loader.get_loading_statistics()

    def shutdown(self) -> None:
        """Shutdown the integrated loader.

        Delegates shutdown to the underlying BackgroundModelLoader instance.
        """
        self.background_loader.shutdown()


# Global integrated loader instance
_integrated_loader: IntegratedBackgroundLoader | None = None


def get_background_loader(
    llm_manager: "LLMManager | None" = None,
) -> IntegratedBackgroundLoader | None:
    """Get the global integrated background loader.

    Args:
        llm_manager: Optional LLM manager instance. If not provided, one will be created.

    Returns:
        The global IntegratedBackgroundLoader instance, or None if background loading is disabled.

    """
    global _integrated_loader
    if _integrated_loader is None:
        # Skip background loader creation during testing
        if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
            logger.info("Skipping background loader creation (testing mode)")
            return None

        if llm_manager is None:
            from .llm_backends import get_llm_manager

            llm_manager = get_llm_manager()
        _integrated_loader = IntegratedBackgroundLoader(llm_manager)
    return _integrated_loader


def load_model_with_progress(
    model_id: str,
    backend_class: type,
    config: "LLMConfig",
    priority: int = 0,
    callback: ProgressCallback | None = None,
) -> LoadingTask:
    """Load a model with progress.

    Args:
        model_id: Unique identifier for the model.
        backend_class: Backend class to instantiate for loading.
        config: Configuration for the LLM backend.
        priority: Loading priority (higher numbers loaded first).
        callback: Optional progress callback for status updates.

    Returns:
        The created LoadingTask instance.

    Falls back to synchronous loading if background loader is disabled.
    """
    loader = get_background_loader()
    if loader is None:
        logger.info("Background loader not initialized for %s, using synchronous fallback", model_id)
        task = LoadingTask(model_id, backend_class, config, priority, callback)
        task.mark_completed(True, None, "Completed synchronously without background loader")
        return task

    if callback:
        loader.add_progress_callback(callback)
    return loader.load_model_in_background(model_id, backend_class, config, priority)


if __name__ == "__main__":
    import os
    import sys

    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

    logging.basicConfig(level=logging.INFO, format="%(name)s - %(levelname)s - %(message)s")
    _main_logger = logging.getLogger(__name__)

    from intellicrack.ai.llm_backends import LLMConfig, LLMProvider, OpenAIBackend

    _main_logger.info("Testing Background Model Loading")
    _main_logger.info("=" * 40)

    console_callback = ConsoleProgressCallback()

    configs = [
        LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-3.5-turbo", api_key="test1"),
        LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test2"),
    ]

    loader = BackgroundModelLoader(max_concurrent_loads=2)

    for i, config in enumerate(configs):
        task = loader.submit_loading_task(
            model_id=f"test-model-{i}",
            backend_class=OpenAIBackend,
            config=config,
            priority=i,
            callback=console_callback,
        )

    _main_logger.info("Monitoring progress...")
    time.sleep(2)

    stats = loader.get_loading_statistics()
    _main_logger.info("Statistics: %s", stats)

    all_tasks = loader.get_all_tasks()
    _main_logger.info("All tasks:")
    for model_id, task in all_tasks.items():
        _main_logger.info("  %s: %s (%.1f%%)", model_id, task.state.value, task.progress * 100)

    loader.shutdown()
    _main_logger.info("Shutdown complete")
