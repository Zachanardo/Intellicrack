"""Task management system for Intellicrack.

This module provides task scheduling, execution, and monitoring capabilities
for asynchronous operations and distributed processing.
"""
import logging
import traceback
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal, pyqtSlot

# Initialize structured logger
try:
    from ..utils.logger import get_logger
    logger = get_logger(__name__)
    STRUCTURED_LOGGING = True
except ImportError:
    # Fallback to traditional logging
    logger = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('[%(levelname)s] %(name)s: %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    STRUCTURED_LOGGING = False


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskSignals(QObject):
    """Signals for task communication."""
    started = pyqtSignal(str)  # task_id
    progress = pyqtSignal(str, int, str)  # task_id, percentage, message
    result = pyqtSignal(str, object)  # task_id, result
    error = pyqtSignal(str, str, str)  # task_id, error_type, error_message
    finished = pyqtSignal(str)  # task_id


# Create a metaclass that resolves the conflict between QRunnable and ABC
class TaskMeta(type(QRunnable), type(ABC)):
    pass

class BaseTask(QRunnable, ABC, metaclass=TaskMeta):
    """Base class for all background tasks."""

    def __init__(self, task_id: Optional[str] = None, description: str = ""):
        """Initialize the base task with ID, description, and status tracking.

        Args:
            task_id: Optional unique identifier for the task
            description: Description of what the task does
        """
        super().__init__()
        self.task_id = task_id or str(uuid.uuid4())
        self.description = description
        self.status = TaskStatus.PENDING
        self.result = None
        self.error = None
        self.start_time = None
        self.end_time = None
        self.progress = 0
        self.should_stop = False
        self.logger = logging.getLogger(__name__)

    def run(self):
        """Execute the task."""
        try:
            self._started_at = datetime.now()
            self.signals.started.emit(self.task_id)
            
            if STRUCTURED_LOGGING:
                logger.info("Task started",
                           task_id=self.task_id,
                           description=self.description,
                           start_time=self._started_at.isoformat(),
                           category="task_execution")
            else:
                logger.info(f"Task started: {self.task_id} - {self.description}")

            # Execute the actual task
            result = self.execute()

            if not self._is_cancelled:
                self.signals.result.emit(self.task_id, result)
                if STRUCTURED_LOGGING:
                    logger.info("Task completed successfully",
                               task_id=self.task_id,
                               description=self.description,
                               duration=str(datetime.now() - self._started_at),
                               category="task_execution")
                else:
                    logger.info(f"Task completed: {self.task_id}")
            else:
                if STRUCTURED_LOGGING:
                    logger.info("Task cancelled",
                               task_id=self.task_id,
                               description=self.description,
                               category="task_execution")
                else:
                    logger.info(f"Task cancelled: {self.task_id}")

        except Exception as e:
            error_type = type(e).__name__
            error_msg = str(e)
            error_traceback = traceback.format_exc()

            if STRUCTURED_LOGGING:
                logger.error("Task execution failed",
                           task_id=self.task_id,
                           description=self.description,
                           error_type=error_type,
                           error_message=error_msg,
                           traceback=error_traceback,
                           category="task_execution")
            else:
                logger.error(f"Task failed: {self.task_id} - {error_type}: {error_msg}")
                logger.debug(f"Traceback: {error_traceback}")

            self.signals.error.emit(self.task_id, error_type, error_msg)

        finally:
            self._finished_at = datetime.now()
            self.signals.finished.emit(self.task_id)

    @abstractmethod
    def execute(self) -> Any:
        """Execute the task logic. Must be implemented by subclasses."""
        pass

    def cancel(self):
        """Cancel the task."""
        self._is_cancelled = True
        if STRUCTURED_LOGGING:
            logger.info("Task cancellation requested",
                       task_id=self.task_id,
                       description=self.description,
                       category="task_execution")
        else:
            logger.info(f"Task cancellation requested: {self.task_id}")

    def is_cancelled(self) -> bool:
        """Check if the task has been cancelled."""
        return self._is_cancelled

    def emit_progress(self, percentage: int, message: str = ""):
        """Emit progress update."""
        if not self._is_cancelled:
            self.signals.progress.emit(self.task_id, percentage, message)


class CallableTask(BaseTask):
    """Task that wraps a callable function."""

    def __init__(self, func: Callable, args: tuple = (), kwargs: dict = None,
                 task_id: Optional[str] = None, description: str = ""):
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
        self.kwargs = kwargs or {}

    def execute(self) -> Any:
        """Execute the wrapped callable."""
        # If the function expects a task parameter, pass self
        import inspect
        sig = inspect.signature(self.func)
        if 'task' in sig.parameters:
            self.kwargs['task'] = self

        return self.func(*self.args, **self.kwargs)


class TaskManager(QObject):
    """Manages background tasks using QThreadPool."""

    # Signals for task manager events
    task_submitted = pyqtSignal(str, str)  # task_id, description
    all_tasks_completed = pyqtSignal()
    active_task_count_changed = pyqtSignal(int)

    def __init__(self, max_thread_count: Optional[int] = None):
        """Initialize the task manager.

        Sets up the Qt thread pool-based task management system for handling
        concurrent background operations. Configures thread pool settings,
        task tracking, and signal connections for progress monitoring.

        Args:
            max_thread_count: Maximum number of concurrent threads. If None, uses Qt default.
        """
        super().__init__()
        self.thread_pool = QThreadPool.globalInstance()

        if max_thread_count:
            self.thread_pool.setMaxThreadCount(max_thread_count)

        self._active_tasks: Dict[str, BaseTask] = {}
        self._task_history: List[Dict] = []
        self._task_results: Dict[str, Any] = {}

        if STRUCTURED_LOGGING:
            logger.info("TaskManager initialized",
                       max_threads=self.thread_pool.maxThreadCount(),
                       category="task_manager")
        else:
            logger.info(f"TaskManager initialized with {self.thread_pool.maxThreadCount()} threads")

    def submit_task(self, task: BaseTask) -> str:
        """Submit a task for execution."""
        # Connect task signals
        task.signals.started.connect(self._on_task_started)
        task.signals.progress.connect(self._on_task_progress)
        task.signals.result.connect(self._on_task_result)
        task.signals.error.connect(self._on_task_error)
        task.signals.finished.connect(self._on_task_finished)

        # Track the task
        self._active_tasks[task.task_id] = task

        # Submit to thread pool
        self.thread_pool.start(task)

        # Emit signals
        self.task_submitted.emit(task.task_id, task.description)
        self.active_task_count_changed.emit(len(self._active_tasks))

        if STRUCTURED_LOGGING:
            logger.info("Task submitted",
                       task_id=task.task_id,
                       description=task.description,
                       active_tasks=len(self._active_tasks),
                       category="task_manager")
        else:
            logger.info(f"Task submitted: {task.task_id} - {task.description}")
        return task.task_id

    def submit_callable(self, func: Callable, args: tuple = (), kwargs: dict = None,
                       task_id: Optional[str] = None, description: str = "") -> str:
        """Submit a callable as a task."""
        task = CallableTask(func, args, kwargs, task_id, description)
        return self.submit_task(task)

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a task by ID."""
        if task_id in self._active_tasks:
            task = self._active_tasks[task_id]
            task.cancel()
            if STRUCTURED_LOGGING:
                logger.info("Task cancelled by manager",
                           task_id=task_id,
                           description=task.description,
                           category="task_manager")
            else:
                logger.info(f"Task cancelled: {task_id}")
            return True
        return False

    def cancel_all_tasks(self):
        """Cancel all active tasks."""
        for task_id in list(self._active_tasks.keys()):
            self.cancel_task(task_id)

    def wait_for_all(self, timeout_ms: int = -1) -> bool:
        """Wait for all tasks to complete."""
        return self.thread_pool.waitForDone(timeout_ms)

    def get_active_tasks(self) -> Dict[str, str]:
        """Get dictionary of active task IDs to descriptions."""
        return {task_id: task.description for task_id, task in self._active_tasks.items()}

    def get_task_result(self, task_id: str) -> Optional[Any]:
        """Get the result of a completed task."""
        return self._task_results.get(task_id)

    def get_task_history(self) -> List[Dict]:
        """Get the history of all tasks."""
        return self._task_history.copy()

    def get_thread_count(self) -> int:
        """Get the maximum thread count."""
        return self.thread_pool.maxThreadCount()

    def set_thread_count(self, count: int):
        """Set the maximum thread count."""
        self.thread_pool.setMaxThreadCount(count)
        if STRUCTURED_LOGGING:
            logger.info("Thread count updated",
                       new_thread_count=count,
                       category="task_manager")
        else:
            logger.info(f"Thread count set to {count}")

    # Private slot methods
    @pyqtSlot(str)
    def _on_task_started(self, task_id: str):
        """Handle task start."""
        if STRUCTURED_LOGGING:
            logger.debug("Task started signal received",
                        task_id=task_id,
                        category="task_manager")
        else:
            logger.debug(f"Task started signal received: {task_id}")

    @pyqtSlot(str, int, str)
    def _on_task_progress(self, task_id: str, percentage: int, message: str):
        """Handle task progress update."""
        if STRUCTURED_LOGGING:
            logger.debug("Task progress update",
                        task_id=task_id,
                        percentage=percentage,
                        message=message,
                        category="task_manager")
        else:
            logger.debug(f"Task progress: {task_id} - {percentage}% - {message}")

    @pyqtSlot(str, object)
    def _on_task_result(self, task_id: str, result: Any):
        """Handle task result."""
        self._task_results[task_id] = result
        if STRUCTURED_LOGGING:
            logger.debug("Task result received",
                        task_id=task_id,
                        result_type=type(result).__name__,
                        category="task_manager")
        else:
            logger.debug(f"Task result received: {task_id}")

    @pyqtSlot(str, str, str)
    def _on_task_error(self, task_id: str, error_type: str, error_message: str):
        """Handle task error."""
        if STRUCTURED_LOGGING:
            logger.error("Task error received",
                        task_id=task_id,
                        error_type=error_type,
                        error_message=error_message,
                        category="task_manager")
        else:
            logger.error(f"Task error: {task_id} - {error_type}: {error_message}")

    @pyqtSlot(str)
    def _on_task_finished(self, task_id: str):
        """Handle task completion."""
        if task_id in self._active_tasks:
            task = self._active_tasks.pop(task_id)

            # Add to history
            history_entry = {
                'task_id': task_id,
                'description': task.description,
                'started_at': task._started_at.isoformat() if task._started_at else None,
                'finished_at': task._finished_at.isoformat() if task._finished_at else None,
                'cancelled': task._is_cancelled
            }
            self._task_history.append(history_entry)

            # Keep history size manageable
            if len(self._task_history) > 100:
                self._task_history = self._task_history[-100:]

            # Emit count change
            self.active_task_count_changed.emit(len(self._active_tasks))

            # Check if all tasks completed
            if not self._active_tasks:
                self.all_tasks_completed.emit()

        if STRUCTURED_LOGGING:
            logger.debug("Task finished",
                        task_id=task_id,
                        remaining_tasks=len(self._active_tasks),
                        category="task_manager")
        else:
            logger.debug(f"Task finished: {task_id}")


class LongRunningTask(BaseTask):
    """Example of a long-running task with progress updates."""

    def __init__(self, duration: int = 10, task_id: Optional[str] = None):
        """Initialize the long running task with specified duration.

        Args:
            duration: Task duration in seconds
            task_id: Optional unique identifier for the task
        """
        super().__init__(task_id, f"Long running task ({duration}s)")
        self.duration = duration

    def execute(self) -> str:
        """Simulate a long-running operation."""
        import asyncio
        import threading

        async def async_execute():
            for i in range(self.duration):
                if self.is_cancelled():
                    return "Task cancelled"

                await asyncio.sleep(1)
                progress = int((i + 1) / self.duration * 100)
                self.emit_progress(progress, f"Processing step {i + 1}/{self.duration}")

            return f"Task completed after {self.duration} seconds"

        # Run async code in synchronous context
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(async_execute())


# Global instance
_task_manager_instance = None


def get_task_manager() -> TaskManager:
    """Get the global TaskManager instance."""
    global _task_manager_instance
    if _task_manager_instance is None:
        _task_manager_instance = TaskManager()
    return _task_manager_instance
