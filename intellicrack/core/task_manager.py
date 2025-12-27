"""Task management system for Intellicrack.

This module provides task scheduling, execution, and monitoring capabilities

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
for asynchronous operations and distributed processing.
"""

import logging
import traceback
import uuid
from abc import ABC, ABCMeta, abstractmethod
from collections.abc import Callable
from datetime import datetime
from enum import Enum
from typing import Any

from intellicrack.handlers.pyqt6_handler import QObject, QRunnable, QThreadPool, pyqtSignal, pyqtSlot
from intellicrack.utils.logger import get_logger


logger = get_logger(__name__)


class TaskStatus(Enum):
    """Task execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Fallback signal class for when PyQt6 is not available
class FallbackSignals:
    """Fallback signals implementation when PyQt6 is not available."""

    def __init__(self) -> None:
        """Initialize fallback signals."""
        self.started = None
        self.progress = None
        self.result = None
        self.error = None
        self.finished = None


if QObject is not None:

    class TaskSignals(QObject):
        """Signals for task communication."""

        started = pyqtSignal(str)
        progress = pyqtSignal(str, int, str)
        result = pyqtSignal(str, object)
        error = pyqtSignal(str, str, str)
        finished = pyqtSignal(str)

else:

    class TaskSignals:  # type: ignore[no-redef,unreachable]
        """Fallback signals implementation when PyQt6 is not available."""

        def __init__(self) -> None:
            """Initialize fallback signals."""
            self.started = None
            self.progress = None
            self.result = None
            self.error = None
            self.finished = None


if QRunnable is not None:

    class TaskMeta(type(QRunnable), ABCMeta):  # type: ignore[misc]
        """Metaclass to resolve conflicts between QRunnable and ABC."""

        pass

    class BaseTask(QRunnable, ABC, metaclass=TaskMeta):
        """Base class for all background tasks."""

        def __init__(self, task_id: str | None = None, description: str = "") -> None:
            """Initialize the base task with ID, description, and status tracking.

            Args:
                task_id: Optional unique identifier for the task
                description: Description of what the task does

            """
            super().__init__()
            self.task_id = task_id or str(uuid.uuid4())
            self.description = description
            self.status = TaskStatus.PENDING
            self.result: Any = None
            self.error: Any = None
            self.start_time: datetime | None = None
            self.end_time: datetime | None = None
            self.progress = 0
            self.should_stop = False
            self.logger = logging.getLogger(__name__)
            self.signals = TaskSignals()
            self._is_cancelled = False
            self._started_at: datetime | None = None
            self._finished_at: datetime | None = None

        def run(self) -> None:
            """Execute the task."""
            try:
                self._started_at = datetime.now()
                self.signals.started.emit(self.task_id)
                logger.info("Task started: %s - %s", self.task_id, self.description)

                result = self.execute()

                if not self._is_cancelled:
                    self.signals.result.emit(self.task_id, result)
                    logger.info("Task completed: %s", self.task_id)
                else:
                    logger.info("Task cancelled: %s", self.task_id)

            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                error_traceback = traceback.format_exc()

                logger.exception("Task failed: %s - %s: %s", self.task_id, error_type, error_msg)
                logger.debug("Traceback: %s", error_traceback)

                self.signals.error.emit(self.task_id, error_type, error_msg)

            finally:
                self._finished_at = datetime.now()
                self.signals.finished.emit(self.task_id)

        @abstractmethod
        def execute(self) -> Any:
            """Execute the task logic. Must be implemented by subclasses."""

        def cancel(self) -> None:
            """Cancel the task."""
            self._is_cancelled = True
            logger.info("Task cancellation requested: %s", self.task_id)

        def is_cancelled(self) -> bool:
            """Check if the task has been cancelled."""
            return self._is_cancelled

        def emit_progress(self, percentage: int, message: str = "") -> None:
            """Emit progress update."""
            if not self._is_cancelled:
                self.signals.progress.emit(self.task_id, percentage, message)

else:

    class BaseTask(ABC):  # type: ignore[no-redef,unreachable]
        """Base class for all background tasks (fallback)."""

        def __init__(self, task_id: str | None = None, description: str = "") -> None:
            """Initialize the base task with ID, description, and status tracking.

            Args:
                task_id: Optional unique identifier for the task
                description: Description of what the task does

            """
            self.task_id = task_id or str(uuid.uuid4())
            self.description = description
            self.status = TaskStatus.PENDING
            self.result: Any = None
            self.error: Any = None
            self.start_time: datetime | None = None
            self.end_time: datetime | None = None
            self.progress = 0
            self.should_stop = False
            self.logger = logging.getLogger(__name__)
            self.signals = TaskSignals()
            self._is_cancelled = False
            self._started_at: datetime | None = None
            self._finished_at: datetime | None = None

        def run(self) -> None:
            """Execute the task."""
            try:
                self._started_at = datetime.now()
                logger.info("Task started: %s - %s", self.task_id, self.description)

                self.execute()

                if not self._is_cancelled:
                    logger.info("Task completed: %s", self.task_id)
                else:
                    logger.info("Task cancelled: %s", self.task_id)

            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                error_traceback = traceback.format_exc()

                logger.exception("Task failed: %s - %s: %s", self.task_id, error_type, error_msg)
                logger.debug("Traceback: %s", error_traceback)

            finally:
                self._finished_at = datetime.now()

        @abstractmethod
        def execute(self) -> Any:
            """Execute the task logic. Must be implemented by subclasses."""

        def cancel(self) -> None:
            """Cancel the task."""
            self._is_cancelled = True
            logger.info("Task cancellation requested: %s", self.task_id)

        def is_cancelled(self) -> bool:
            """Check if the task has been cancelled."""
            return self._is_cancelled

        def emit_progress(self, percentage: int, message: str = "") -> None:
            """Emit progress update.

            Args:
                percentage: Progress percentage (0-100).
                message: Optional progress message.

            """
            logger.debug("Task %s progress: %d%% - %s", self.task_id, percentage, message)


class CallableTask(BaseTask):
    """Task that wraps a callable function."""

    def __init__(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
        task_id: str | None = None,
        description: str = "",
    ) -> None:
        """Initialize the callable task with function, arguments, and task metadata.

        Args:
            func: The callable function to execute
            args: Positional arguments for the function
            kwargs: Keyword arguments for the function
            task_id: Optional unique identifier for the task
            description: Description of what the task does

        """
        super().__init__(task_id, description)
        self.func = func
        self.args = args
        self.kwargs = kwargs if kwargs is not None else {}

    def execute(self) -> Any:
        """Execute the wrapped callable."""
        import inspect

        sig = inspect.signature(self.func)
        if "task" in sig.parameters:
            self.kwargs["task"] = self

        return self.func(*self.args, **self.kwargs)


if QObject is not None and QThreadPool is not None:

    class TaskManager(QObject):
        """Manages background tasks using QThreadPool."""

        task_submitted = pyqtSignal(str, str)
        all_tasks_completed = pyqtSignal()
        active_task_count_changed = pyqtSignal(int)

        def __init__(self, max_thread_count: int | None = None) -> None:
            """Initialize the task manager.

            Sets up the Qt thread pool-based task management system for handling
            concurrent background operations. Configures thread pool settings,
            task tracking, and signal connections for progress monitoring.

            Args:
                max_thread_count: Maximum number of concurrent threads. If None, uses Qt default.

            """
            super().__init__()
            self.thread_pool = QThreadPool.globalInstance()

            if max_thread_count is not None and self.thread_pool is not None:
                self.thread_pool.setMaxThreadCount(max_thread_count)

            self._active_tasks: dict[str, BaseTask] = {}
            self._task_history: list[dict[str, Any]] = []
            self._task_results: dict[str, Any] = {}

            if self.thread_pool is not None:
                logger.info("TaskManager initialized with %d threads", self.thread_pool.maxThreadCount())
            else:
                logger.warning("TaskManager initialized without thread pool")

        def submit_task(self, task: BaseTask) -> str:
            """Submit a task for execution."""
            task.signals.started.connect(self._on_task_started)
            task.signals.progress.connect(self._on_task_progress)
            task.signals.result.connect(self._on_task_result)
            task.signals.error.connect(self._on_task_error)
            task.signals.finished.connect(self._on_task_finished)

            self._active_tasks[task.task_id] = task

            if self.thread_pool is not None:
                self.thread_pool.start(task)

            self.task_submitted.emit(task.task_id, task.description)
            self.active_task_count_changed.emit(len(self._active_tasks))

            logger.info("Task submitted: %s - %s", task.task_id, task.description)
            return task.task_id

        def submit_callable(
            self,
            func: Callable[..., Any],
            args: tuple[Any, ...] = (),
            kwargs: dict[str, Any] | None = None,
            task_id: str | None = None,
            description: str = "",
        ) -> str:
            """Submit a callable as a task."""
            task = CallableTask(func, args, kwargs, task_id, description)
            return self.submit_task(task)

        def cancel_task(self, task_id: str) -> bool:
            """Cancel a task by ID."""
            if task_id in self._active_tasks:
                task = self._active_tasks[task_id]
                task.cancel()
                logger.info("Task cancelled: %s", task_id)
                return True
            return False

        def cancel_all_tasks(self) -> None:
            """Cancel all active tasks."""
            for task_id in list(self._active_tasks):
                self.cancel_task(task_id)

        def wait_for_all(self, timeout_ms: int = -1) -> bool:
            """Wait for all tasks to complete."""
            if self.thread_pool is not None:
                return self.thread_pool.waitForDone(timeout_ms)
            return True

        def get_active_tasks(self) -> dict[str, str]:
            """Get dictionary of active task IDs to descriptions."""
            return {task_id: task.description for task_id, task in self._active_tasks.items()}

        def get_task_result(self, task_id: str) -> Any:
            """Get the result of a completed task."""
            return self._task_results.get(task_id)

        def get_task_history(self) -> list[dict[str, Any]]:
            """Get the history of all tasks."""
            return self._task_history.copy()

        def get_thread_count(self) -> int:
            """Get the maximum thread count."""
            if self.thread_pool is not None:
                return self.thread_pool.maxThreadCount()
            return 0

        def set_thread_count(self, count: int) -> None:
            """Set the maximum thread count."""
            if self.thread_pool is not None:
                self.thread_pool.setMaxThreadCount(count)
                logger.info("Thread count set to %d", count)

        @pyqtSlot(str)
        def _on_task_started(self, task_id: str) -> None:
            """Handle task start."""
            logger.debug("Task started signal received: %s", task_id)

        @pyqtSlot(str, int, str)
        def _on_task_progress(self, task_id: str, percentage: int, message: str) -> None:
            """Handle task progress update."""
            logger.debug("Task progress: %s - %d%% - %s", task_id, percentage, message)

        @pyqtSlot(str, object)
        def _on_task_result(self, task_id: str, result: Any) -> None:
            """Handle task result."""
            self._task_results[task_id] = result
            logger.debug("Task result received: %s", task_id)

        @pyqtSlot(str, str, str)
        def _on_task_error(self, task_id: str, error_type: str, error_message: str) -> None:
            """Handle task error."""
            logger.error("Task error: %s - %s: %s", task_id, error_type, error_message)

        @pyqtSlot(str)
        def _on_task_finished(self, task_id: str) -> None:
            """Handle task completion."""
            if task_id in self._active_tasks:
                task = self._active_tasks.pop(task_id)

                history_entry: dict[str, Any] = {
                    "task_id": task_id,
                    "description": task.description,
                    "started_at": task._started_at.isoformat() if task._started_at else None,
                    "finished_at": task._finished_at.isoformat() if task._finished_at else None,
                    "cancelled": task._is_cancelled,
                }
                self._task_history.append(history_entry)

                if len(self._task_history) > 100:
                    self._task_history = self._task_history[-100:]

                self.active_task_count_changed.emit(len(self._active_tasks))

                if not self._active_tasks:
                    self.all_tasks_completed.emit()

            logger.debug("Task finished: %s", task_id)

else:

    class TaskManager:  # type: ignore[no-redef,unreachable]
        """Fallback TaskManager when PyQt6 is not available."""

        def __init__(self, max_thread_count: int | None = None) -> None:
            """Initialize the task manager fallback."""
            self._active_tasks: dict[str, BaseTask] = {}
            self._task_history: list[dict[str, Any]] = []
            self._task_results: dict[str, Any] = {}
            logger.warning("TaskManager initialized in fallback mode without PyQt6")

        def submit_task(self, task: BaseTask) -> str:
            """Submit a task for execution (fallback)."""
            logger.warning("TaskManager fallback: cannot submit task %s", task.task_id)
            return task.task_id

        def submit_callable(
            self,
            func: Callable[..., Any],
            args: tuple[Any, ...] = (),
            kwargs: dict[str, Any] | None = None,
            task_id: str | None = None,
            description: str = "",
        ) -> str:
            """Submit a callable as a task (fallback)."""
            logger.warning("TaskManager fallback: cannot submit callable")
            return task_id or str(uuid.uuid4())

        def cancel_task(self, task_id: str) -> bool:
            """Cancel a task by ID (fallback)."""
            return False

        def cancel_all_tasks(self) -> None:
            """Cancel all active tasks (fallback)."""
            pass

        def wait_for_all(self, timeout_ms: int = -1) -> bool:
            """Wait for all tasks to complete (fallback)."""
            return True

        def get_active_tasks(self) -> dict[str, str]:
            """Get dictionary of active task IDs to descriptions (fallback)."""
            return {}

        def get_task_result(self, task_id: str) -> Any:
            """Get the result of a completed task (fallback)."""
            return None

        def get_task_history(self) -> list[dict[str, Any]]:
            """Get the history of all tasks (fallback)."""
            return []

        def get_thread_count(self) -> int:
            """Get the maximum thread count (fallback)."""
            return 0

        def set_thread_count(self, count: int) -> None:
            """Set the maximum thread count (fallback)."""
            pass


_task_manager_instance: TaskManager | None = None


def get_task_manager() -> TaskManager:
    """Get the global TaskManager instance."""
    global _task_manager_instance
    if _task_manager_instance is None:
        _task_manager_instance = TaskManager()
    return _task_manager_instance
