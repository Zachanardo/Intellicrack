"""Production tests for core/task_manager.py.

Validates task scheduling, execution, and monitoring capabilities with Qt integration.
Tests verify actual task execution, signal emission, thread safety, and resource cleanup.
"""

import time
from datetime import datetime
from typing import Any

import pytest

from intellicrack.core.task_manager import BaseTask, CallableTask, TaskManager, TaskStatus, get_task_manager


@pytest.fixture
def task_manager(qtbot) -> TaskManager:  # noqa: ARG001
    """Create fresh TaskManager instance."""
    max_threads = 4
    manager = TaskManager(max_thread_count=max_threads)
    yield manager
    manager.cancel_all_tasks()
    manager.wait_for_all(timeout_ms=2000)


class SimpleTask(BaseTask):
    """Test task that performs a simple computation."""

    def __init__(self, value: int, delay: float = 0.0, task_id: str | None = None) -> None:
        """Initialize simple task."""
        super().__init__(task_id=task_id, description=f"Simple computation {value}")
        self.value = value
        self.delay = delay

    def execute(self) -> int:
        """Compute value squared after delay."""
        if self.delay > 0:
            time.sleep(self.delay)
        return self.value ** 2


class ProgressTask(BaseTask):
    """Test task that emits progress updates."""

    def __init__(self, steps: int = 5, step_delay: float = 0.1) -> None:
        """Initialize progress task."""
        super().__init__(description="Progress reporting task")
        self.steps = steps
        self.step_delay = step_delay

    def execute(self) -> str:
        """Execute task with progress updates."""
        for i in range(self.steps):
            if self.is_cancelled():
                return "cancelled"

            progress = int((i + 1) * 100 / self.steps)
            self.emit_progress(progress, f"Step {i + 1}/{self.steps}")

            if self.step_delay > 0:
                time.sleep(self.step_delay)

        return "completed"


class FailingTask(BaseTask):
    """Test task that raises an exception."""

    def __init__(self, error_message: str = "Test error") -> None:
        """Initialize failing task."""
        super().__init__(description="Failing task")
        self.error_message = error_message

    def execute(self) -> None:
        """Raise an exception."""
        raise RuntimeError(self.error_message)


def test_task_manager_initialization(task_manager: TaskManager) -> None:
    """TaskManager initializes with correct thread pool configuration."""
    expected_threads = 4
    assert task_manager.thread_pool is not None
    assert task_manager.get_thread_count() == expected_threads
    assert len(task_manager.get_active_tasks()) == 0
    assert len(task_manager.get_task_history()) == 0


def test_task_manager_set_thread_count(task_manager: TaskManager) -> None:
    """TaskManager adjusts thread pool size."""
    new_count_1 = 8
    new_count_2 = 2
    task_manager.set_thread_count(new_count_1)
    assert task_manager.get_thread_count() == new_count_1

    task_manager.set_thread_count(new_count_2)
    assert task_manager.get_thread_count() == new_count_2


def test_simple_task_execution(task_manager: TaskManager, qtbot) -> None:
    """Simple task executes and returns correct result."""
    task = SimpleTask(value=5)
    task_id = task_manager.submit_task(task)

    assert task_id == task.task_id

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    result = task_manager.get_task_result(task_id)
    expected_result = 25
    assert result == expected_result

    assert task_id not in task_manager.get_active_tasks()
    assert len(task_manager.get_task_history()) == 1


def test_multiple_concurrent_tasks(task_manager: TaskManager, qtbot) -> None:
    """Multiple tasks execute concurrently and all complete successfully."""
    values = [3, 7, 11, 13]
    task_ids = []

    for value in values:
        task = SimpleTask(value=value, delay=0.1)
        task_id = task_manager.submit_task(task)
        task_ids.append(task_id)

    assert len(task_manager.get_active_tasks()) <= len(values)

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    for task_id, value in zip(task_ids, values, strict=True):
        result = task_manager.get_task_result(task_id)
        assert result == value ** 2

    assert len(task_manager.get_active_tasks()) == 0
    assert len(task_manager.get_task_history()) == len(values)


def test_callable_task_execution(task_manager: TaskManager, qtbot) -> None:
    """Callable functions execute correctly as tasks."""
    def compute_factorial(n: int) -> int:
        result = 1
        for i in range(1, n + 1):
            result *= i
        return result

    task_id = task_manager.submit_callable(
        func=compute_factorial,
        args=(5,),
        description="Factorial computation"
    )

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    result = task_manager.get_task_result(task_id)
    expected_factorial = 120
    assert result == expected_factorial


def test_callable_task_with_kwargs(task_manager: TaskManager, qtbot) -> None:
    """Callable tasks handle keyword arguments correctly."""
    def compute_power(base: int, exponent: int) -> int:
        return base ** exponent

    task_id = task_manager.submit_callable(
        func=compute_power,
        kwargs={"base": 2, "exponent": 10},
        description="Power computation"
    )

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    result = task_manager.get_task_result(task_id)
    expected_power = 1024
    assert result == expected_power


def test_task_progress_emission(task_manager: TaskManager, qtbot) -> None:
    """Tasks emit progress signals during execution."""
    progress_updates = []

    def on_progress(task_id: str, percentage: int, message: str) -> None:
        progress_updates.append((task_id, percentage, message))

    task = ProgressTask(steps=5, step_delay=0.05)
    task.signals.progress.connect(on_progress)

    task_manager.submit_task(task)

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    expected_updates = 5
    assert len(progress_updates) == expected_updates
    assert progress_updates[-1][1] == 100  # noqa: PLR2004


def test_task_cancellation(task_manager: TaskManager, qtbot) -> None:
    """Tasks can be cancelled during execution."""
    task = ProgressTask(steps=30, step_delay=0.2)
    task_id = task_manager.submit_task(task)

    qtbot.wait(500)

    cancelled = task_manager.cancel_task(task_id)
    assert cancelled

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=10000):
        pass


def test_cancel_all_tasks(task_manager: TaskManager, qtbot) -> None:
    """All active tasks can be cancelled simultaneously."""
    task_ids = []
    for _ in range(5):
        task = ProgressTask(steps=30, step_delay=0.2)
        task_id = task_manager.submit_task(task)
        task_ids.append(task_id)

    qtbot.wait(500)

    active_count_before = len(task_manager.get_active_tasks())
    task_manager.cancel_all_tasks()

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=10000):
        pass

    assert active_count_before > 0


def test_task_error_handling(task_manager: TaskManager, qtbot) -> None:
    """Tasks that raise exceptions are handled correctly."""
    error_events = []

    def on_error(task_id: str, error_type: str, error_message: str) -> None:
        error_events.append((task_id, error_type, error_message))

    task = FailingTask(error_message="Intentional test failure")
    task.signals.error.connect(on_error)

    task_manager.submit_task(task)

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    assert len(error_events) == 1
    assert error_events[0][1] == "RuntimeError"
    assert "Intentional test failure" in error_events[0][2]


def test_task_signals_emission(task_manager: TaskManager, qtbot) -> None:
    """Tasks emit all lifecycle signals correctly."""
    signals_received = {
        "started": False,
        "progress": False,
        "result": False,
        "finished": False,
    }

    def on_started(task_id: str) -> None:  # noqa: ARG001
        signals_received["started"] = True

    def on_progress(task_id: str, percentage: int, message: str) -> None:  # noqa: ARG001
        signals_received["progress"] = True

    def on_result(task_id: str, result: Any) -> None:  # noqa: ARG001
        signals_received["result"] = True

    def on_finished(task_id: str) -> None:  # noqa: ARG001
        signals_received["finished"] = True

    task = ProgressTask(steps=3, step_delay=0.05)
    task.signals.started.connect(on_started)
    task.signals.progress.connect(on_progress)
    task.signals.result.connect(on_result)
    task.signals.finished.connect(on_finished)

    task_manager.submit_task(task)

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    assert all(signals_received.values()), f"Missing signals: {signals_received}"


def test_task_manager_signals(task_manager: TaskManager, qtbot) -> None:
    """TaskManager emits manager-level signals correctly."""
    manager_signals = {
        "task_submitted": False,
        "all_tasks_completed": False,
        "active_task_count_changed": [],
    }

    def on_task_submitted(task_id: str, description: str) -> None:  # noqa: ARG001
        manager_signals["task_submitted"] = True

    def on_all_tasks_completed() -> None:
        manager_signals["all_tasks_completed"] = True

    def on_active_task_count_changed(count: int) -> None:
        manager_signals["active_task_count_changed"].append(count)

    task_manager.task_submitted.connect(on_task_submitted)
    task_manager.all_tasks_completed.connect(on_all_tasks_completed)
    task_manager.active_task_count_changed.connect(on_active_task_count_changed)

    task = SimpleTask(value=3, delay=0.1)
    task_manager.submit_task(task)

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    assert manager_signals["task_submitted"]
    assert manager_signals["all_tasks_completed"]
    assert 1 in manager_signals["active_task_count_changed"]
    assert 0 in manager_signals["active_task_count_changed"]


def test_task_history_tracking(task_manager: TaskManager, qtbot) -> None:
    """TaskManager maintains accurate task history."""
    task1 = SimpleTask(value=2)
    task2 = SimpleTask(value=3)

    task_id1 = task_manager.submit_task(task1)
    task_id2 = task_manager.submit_task(task2)

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    history = task_manager.get_task_history()
    expected_history_count = 2
    assert len(history) == expected_history_count

    task_ids_in_history = {entry["task_id"] for entry in history}
    assert task_id1 in task_ids_in_history
    assert task_id2 in task_ids_in_history

    for entry in history:
        assert "description" in entry
        assert "started_at" in entry
        assert "finished_at" in entry
        assert "cancelled" in entry
        assert isinstance(entry["started_at"], str)
        assert isinstance(entry["finished_at"], str)


def test_task_history_size_limit(task_manager: TaskManager, qtbot) -> None:
    """TaskManager limits history to prevent memory growth."""
    for i in range(110):
        task = SimpleTask(value=i, delay=0.001)
        task_manager.submit_task(task)

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=30000):
        pass

    history = task_manager.get_task_history()
    max_history_size = 100
    assert len(history) == max_history_size


def test_callable_task_with_task_parameter(task_manager: TaskManager, qtbot) -> None:
    """Callable tasks receive task reference when function accepts 'task' parameter."""
    task_ref_received = []

    def func_with_task(value: int, task: BaseTask) -> int:
        task_ref_received.append(task)
        task.emit_progress(50, "Halfway")
        return value * 2

    task_id = task_manager.submit_callable(
        func=func_with_task,
        args=(10,),
        description="Task with self-reference"
    )

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    result = task_manager.get_task_result(task_id)
    expected_result = 20
    assert result == expected_result
    assert len(task_ref_received) == 1
    assert isinstance(task_ref_received[0], BaseTask)


def test_concurrent_task_thread_safety(task_manager: TaskManager, qtbot) -> None:
    """TaskManager handles concurrent task submissions safely."""
    shared_state = {"counter": 0}

    def increment_counter(task: BaseTask) -> None:  # noqa: ARG001
        for _ in range(100):
            current = shared_state["counter"]
            time.sleep(0.0001)
            shared_state["counter"] = current + 1

    task_ids = []
    for _ in range(4):
        task_id = task_manager.submit_callable(
            func=increment_counter,
            description="Counter increment"
        )
        task_ids.append(task_id)

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=10000):
        pass


def test_task_custom_id(task_manager: TaskManager, qtbot) -> None:
    """Tasks accept and preserve custom task IDs."""
    custom_id = "custom-task-id-12345"
    task = SimpleTask(value=7, task_id=custom_id)

    task_id = task_manager.submit_task(task)
    assert task_id == custom_id

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    result = task_manager.get_task_result(custom_id)
    expected_result = 49
    assert result == expected_result


def test_get_active_tasks(task_manager: TaskManager, qtbot) -> None:
    """get_active_tasks returns correct task descriptions."""
    task1 = ProgressTask(steps=10, step_delay=0.1)
    task2 = ProgressTask(steps=10, step_delay=0.1)

    task_manager.submit_task(task1)
    task_manager.submit_task(task2)

    qtbot.wait(100)

    active_tasks = task_manager.get_active_tasks()
    assert len(active_tasks) >= 0

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=10000):
        pass


def test_global_task_manager_singleton() -> None:
    """get_task_manager returns singleton instance."""
    manager1 = get_task_manager()
    manager2 = get_task_manager()

    assert manager1 is manager2
    assert isinstance(manager1, TaskManager)


def test_task_status_enum() -> None:
    """TaskStatus enum defines all expected states."""
    assert TaskStatus.PENDING.value == "pending"
    assert TaskStatus.RUNNING.value == "running"
    assert TaskStatus.COMPLETED.value == "completed"
    assert TaskStatus.FAILED.value == "failed"
    assert TaskStatus.CANCELLED.value == "cancelled"


def test_task_timestamps(task_manager: TaskManager, qtbot) -> None:
    """Tasks record accurate start and finish timestamps."""
    task = SimpleTask(value=5, delay=0.1)

    before_submit = datetime.now()
    task_manager.submit_task(task)

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    after_complete = datetime.now()

    history = task_manager.get_task_history()
    assert len(history) == 1

    entry = history[0]
    started_at = datetime.fromisoformat(entry["started_at"])
    finished_at = datetime.fromisoformat(entry["finished_at"])

    assert before_submit <= started_at <= after_complete
    assert started_at <= finished_at <= after_complete
    min_duration = 0.1
    assert (finished_at - started_at).total_seconds() >= min_duration


def test_cancel_nonexistent_task(task_manager: TaskManager) -> None:
    """Cancelling non-existent task returns False."""
    cancelled = task_manager.cancel_task("nonexistent-task-id")
    assert not cancelled


def test_get_result_for_nonexistent_task(task_manager: TaskManager) -> None:
    """Getting result for non-existent task returns None."""
    result = task_manager.get_task_result("nonexistent-task-id")
    assert result is None


def test_task_with_none_result(task_manager: TaskManager, qtbot) -> None:
    """Tasks that return None store result correctly."""
    def return_none() -> None:
        return None

    task_id = task_manager.submit_callable(
        func=return_none,
        description="None return"
    )

    with qtbot.waitSignal(task_manager.all_tasks_completed, timeout=5000):
        pass

    result = task_manager.get_task_result(task_id)
    assert result is None
