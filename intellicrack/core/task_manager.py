from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal, pyqtSlot
from typing import Callable, Any, Dict, Optional, List
from abc import ABC, abstractmethod
import traceback
import uuid
from datetime import datetime
from intellicrack.logger import get_logger

logger = get_logger(__name__)


class TaskSignals(QObject):
    """Signals for task communication."""
    started = pyqtSignal(str)  # task_id
    progress = pyqtSignal(str, int, str)  # task_id, percentage, message
    result = pyqtSignal(str, object)  # task_id, result
    error = pyqtSignal(str, str, str)  # task_id, error_type, error_message
    finished = pyqtSignal(str)  # task_id


class BaseTask(QRunnable, ABC):
    """Base class for all background tasks."""
    
    def __init__(self, task_id: Optional[str] = None, description: str = ""):
        super().__init__()
        self.task_id = task_id or str(uuid.uuid4())
        self.description = description
        self.signals = TaskSignals()
        self._is_cancelled = False
        self._started_at = None
        self._finished_at = None
        
    def run(self):
        """Execute the task."""
        try:
            self._started_at = datetime.now()
            self.signals.started.emit(self.task_id)
            logger.info(f"Task started: {self.task_id} - {self.description}")
            
            # Execute the actual task
            result = self.execute()
            
            if not self._is_cancelled:
                self.signals.result.emit(self.task_id, result)
                logger.info(f"Task completed: {self.task_id}")
            else:
                logger.info(f"Task cancelled: {self.task_id}")
                
        except Exception as e:
            error_type = type(e).__name__
            error_msg = str(e)
            error_traceback = traceback.format_exc()
            
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
        super().__init__()
        self.thread_pool = QThreadPool.globalInstance()
        
        if max_thread_count:
            self.thread_pool.setMaxThreadCount(max_thread_count)
            
        self._active_tasks: Dict[str, BaseTask] = {}
        self._task_history: List[Dict] = []
        self._task_results: Dict[str, Any] = {}
        
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
        logger.info(f"Thread count set to {count}")
    
    # Private slot methods
    @pyqtSlot(str)
    def _on_task_started(self, task_id: str):
        """Handle task start."""
        logger.debug(f"Task started signal received: {task_id}")
    
    @pyqtSlot(str, int, str)
    def _on_task_progress(self, task_id: str, percentage: int, message: str):
        """Handle task progress update."""
        logger.debug(f"Task progress: {task_id} - {percentage}% - {message}")
    
    @pyqtSlot(str, object)
    def _on_task_result(self, task_id: str, result: Any):
        """Handle task result."""
        self._task_results[task_id] = result
        logger.debug(f"Task result received: {task_id}")
    
    @pyqtSlot(str, str, str)
    def _on_task_error(self, task_id: str, error_type: str, error_message: str):
        """Handle task error."""
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
        
        logger.debug(f"Task finished: {task_id}")


class LongRunningTask(BaseTask):
    """Example of a long-running task with progress updates."""
    
    def __init__(self, duration: int = 10, task_id: Optional[str] = None):
        super().__init__(task_id, f"Long running task ({duration}s)")
        self.duration = duration
    
    def execute(self) -> str:
        """Simulate a long-running operation."""
        import time
        
        for i in range(self.duration):
            if self.is_cancelled():
                return "Task cancelled"
            
            time.sleep(1)
            progress = int((i + 1) / self.duration * 100)
            self.emit_progress(progress, f"Processing step {i + 1}/{self.duration}")
        
        return f"Task completed after {self.duration} seconds"


# Global instance
_task_manager_instance = None


def get_task_manager() -> TaskManager:
    """Get the global TaskManager instance."""
    global _task_manager_instance
    if _task_manager_instance is None:
        _task_manager_instance = TaskManager()
    return _task_manager_instance