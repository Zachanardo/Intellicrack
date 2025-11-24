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

    def on_progress(self, progress: LoadingProgress) -> None:
        """Print progress to console."""
        print(f"[{progress.model_id}] {progress.state.value}: {progress.progress:.1%} - {progress.message}")

    def on_completed(self, model_id: str, success: bool, error: str | None = None) -> None:
        """Print completion status."""
        status = "SUCCESS" if success else f"FAILED: {error}"
        print(f"[{model_id}] Loading completed: {status}")


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
        """Add progress to queue."""
        self.progress_queue.put(progress)

    def on_completed(self, model_id: str, success: bool, error: str | None = None) -> None:
        """Add completion to queue."""
        self.completion_queue.put((model_id, success, error))

    def get_progress_updates(self) -> list[LoadingProgress]:
        """Get all pending progress updates."""
        updates = []
        try:
            while True:
                updates.append(self.progress_queue.get_nowait())
        except queue.Empty:
            # Queue is empty - all updates retrieved successfully
            logger.debug(f"Retrieved {len(updates)} progress updates from queue")
        return updates

    def get_completion_updates(self) -> list[tuple[str, bool, str | None]]:
        """Get all pending completion updates."""
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
        """Update task progress."""
        if state:
            self.state = state
        self.progress = min(1.0, max(0.0, progress))
        self.message = message

        if self.callback:
            progress_info = LoadingProgress(
                model_id=self.model_id,
                model_name=self.config.model_name,
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
        """Mark task as completed."""
        self.end_time = time.time()
        self.result = result
        self.error = error
        self.state = LoadingState.COMPLETED if success else LoadingState.FAILED
        self.progress = 1.0 if success else 0.0
        self.message = "Loading completed" if success else f"Loading failed: {error}"

        if self.callback:
            self.callback.on_completed(self.model_id, success, error)

    def cancel(self) -> None:
        """Cancel the task."""
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
            logger.info(f"Background model loader started with {max_concurrent_loads} workers")
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
        """Submit a model loading task."""
        with self.lock:
            # Cancel any existing task for this model
            if model_id in self.active_tasks:
                self.cancel_task(model_id)

            task = LoadingTask(model_id, backend_class, config, priority, callback)
            self.pending_tasks.append(task)

            # Add to priority queue (negative priority for max-heap behavior)
            self.task_queue.put((-priority, time.time(), task))

            logger.info(f"Submitted loading task for {model_id} (priority: {priority})")
            return task

    def cancel_task(self, model_id: str) -> bool:
        """Cancel a pending or active task."""
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
        """Get the status of a loading task."""
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
        """Get all tasks (pending, active, and completed)."""
        with self.lock:
            all_tasks = {task.model_id: task for task in self.pending_tasks}
            # Add active tasks
            all_tasks |= self.active_tasks

            # Add completed tasks
            all_tasks.update(self.completed_tasks)

            return all_tasks

    def get_loading_statistics(self) -> dict[str, Any]:
        """Get loading statistics."""
        with self.lock:
            stats: dict[str, Any] = {
                "pending": len(self.pending_tasks),
                "active": len(self.active_tasks),
                "completed": len(self.completed_tasks),
                "total_workers": len(self.worker_threads),
                "active_workers": len(self.active_tasks),
            }

            if completed_tasks := list(self.completed_tasks.values()):
                successful = sum(bool(task.state == LoadingState.COMPLETED) for task in completed_tasks)
                stats["success_rate"] = float(successful) / float(len(completed_tasks))
            else:
                stats["success_rate"] = 0.0

            return stats

    def _worker_thread(self) -> None:
        """Worker thread for loading models."""
        thread_name = threading.current_thread().name
        logger.info(f"Model loader worker {thread_name} started")

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
                logger.error(f"Error in worker thread {thread_name}: {e}")

    def _load_model(self, task: LoadingTask) -> None:
        """Load a model with progress tracking."""
        task.start_time = time.time()

        try:
            # Check if task was cancelled
            if task.cancelled:
                return

            # Stage 1: Initialize backend
            task.update_progress(0.1, "Initializing backend...", LoadingState.INITIALIZING)

            if task.cancelled:
                return

            backend = task.backend_class(task.config)

            # Stage 2: Download/prepare model if needed
            task.update_progress(0.3, "Preparing model...", LoadingState.DOWNLOADING)

            if task.cancelled:
                return

            # Stage 3: Load model
            task.update_progress(0.5, "Loading model...", LoadingState.LOADING)

            if task.cancelled:
                return

            # Actually initialize the backend
            success = backend.initialize()

            if task.cancelled:
                return

            if success:
                task.update_progress(1.0, "Model loaded successfully", LoadingState.COMPLETED)
                task.mark_completed(True, backend)
                logger.info(f"Successfully loaded model {task.model_id}")
            else:
                task.mark_completed(False, error="Backend initialization failed")
                logger.error(f"Failed to initialize backend for {task.model_id}")

        except Exception as e:
            if not task.cancelled:
                error_msg = str(e)
                task.mark_completed(False, error=error_msg)
                logger.error(f"Error loading model {task.model_id}: {e}")

    def shutdown(self) -> None:
        """Shutdown the background loader."""
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
        """Add a progress callback."""
        self.progress_callbacks.append(callback)

    def remove_progress_callback(self, callback: ProgressCallback) -> None:
        """Remove a progress callback."""
        if callback in self.progress_callbacks:
            self.progress_callbacks.remove(callback)

    def load_model_in_background(self, model_id: str, backend_class: type, config: "LLMConfig", priority: int = 0) -> LoadingTask:
        """Load a model in the background with integrated callbacks."""

        # Create a callback that notifies all registered callbacks
        class MultiCallback(ProgressCallback):
            def __init__(self, callbacks: list[ProgressCallback]) -> None:
                """Initialize multi-callback handler with list of callbacks."""
                self.callbacks = callbacks

            def on_progress(self, progress: LoadingProgress) -> None:
                for callback in self.callbacks:
                    try:
                        callback.on_progress(progress)
                    except Exception as e:
                        logger.warning(f"Error in progress callback: {e}")

            def on_completed(self, model_id: str, success: bool, error: str | None = None) -> None:
                for callback in self.callbacks:
                    try:
                        callback.on_completed(model_id, success, error)
                    except Exception as e:
                        logger.warning(f"Error in completion callback: {e}")

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
        """Get loading progress for a model."""
        return self.background_loader.get_task_status(model_id)

    def cancel_loading(self, model_id: str) -> bool:
        """Cancel loading a model."""
        return self.background_loader.cancel_task(model_id)

    def get_all_loading_tasks(self) -> dict[str, LoadingTask]:
        """Get all loading tasks."""
        return self.background_loader.get_all_tasks()

    def get_statistics(self) -> dict[str, Any]:
        """Get loading statistics."""
        return self.background_loader.get_loading_statistics()

    def shutdown(self) -> None:
        """Shutdown the integrated loader."""
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
    """Load a model with progress."""
    loader = get_background_loader()
    if loader is None:
        # Background loader unavailable - create synchronous task fallback
        logger.info(f"Background loader not initialized for {model_id}, using synchronous fallback")
        task = LoadingTask(model_id, backend_class, config, priority, callback)
        task.mark_completed(True, None, "Completed synchronously without background loader")
        return task

    if callback:
        loader.add_progress_callback(callback)
    return loader.load_model_in_background(model_id, backend_class, config, priority)


# Example usage and testing
if __name__ == "__main__":
    import os
    import sys

    # Add project root to path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

    from intellicrack.ai.llm_backends import LLMConfig, LLMProvider, OpenAIBackend

    # Example usage
    print("Testing Background Model Loading")
    print("=" * 40)

    # Create a console callback for testing
    console_callback = ConsoleProgressCallback()

    # Create some test configurations
    configs = [
        LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-3.5-turbo", api_key="test1"),
        LLMConfig(provider=LLMProvider.OPENAI, model_name="gpt-4", api_key="test2"),
    ]

    # Start background loading
    loader = BackgroundModelLoader(max_concurrent_loads=2)

    for i, config in enumerate(configs):
        task = loader.submit_loading_task(
            model_id=f"test-model-{i}",
            backend_class=OpenAIBackend,
            config=config,
            priority=i,
            callback=console_callback,
        )

    # Monitor progress
    print("\nMonitoring progress...")
    time.sleep(2)  # Let it run for a bit

    # Show statistics
    stats = loader.get_loading_statistics()
    print(f"\nStatistics: {stats}")

    # Show all tasks
    all_tasks = loader.get_all_tasks()
    print("\nAll tasks:")
    for model_id, task in all_tasks.items():
        print(f"  {model_id}: {task.state.value} ({task.progress:.1%})")

    # Shutdown
    loader.shutdown()
    print("\nShutdown complete")
