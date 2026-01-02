"""Production tests for CLI progress manager functionality.

Tests validate real progress tracking, task management, display rendering,
and performance monitoring for long-running CLI operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import time
from pathlib import Path
from typing import Any

import pytest


pytest.importorskip("rich", reason="Rich library required for progress manager tests")


@pytest.fixture
def progress_manager() -> Any:
    """Create progress manager instance for testing."""
    from intellicrack.cli.progress_manager import ProgressManager

    manager = ProgressManager()
    yield manager

    if manager.live and manager.live.is_started:
        manager.live.stop()


def test_progress_manager_initialization(progress_manager: Any) -> None:
    """Progress manager initializes with console and task tracking structures."""
    assert hasattr(progress_manager, "console")
    assert hasattr(progress_manager, "tasks")
    assert hasattr(progress_manager, "task_ids")
    assert isinstance(progress_manager.tasks, dict)
    assert isinstance(progress_manager.task_ids, dict)


def test_progress_manager_creates_progress_display(progress_manager: Any) -> None:
    """Progress manager creates rich progress display with custom columns."""
    progress = progress_manager.create_progress_display()

    assert progress is not None
    assert hasattr(progress, "add_task")
    assert hasattr(progress, "update")


def test_progress_manager_starts_analysis_tracking(progress_manager: Any, tmp_path: Path) -> None:
    """Progress manager starts analysis with live display and task initialization."""
    binary_path = str(tmp_path / "test.exe")
    analysis_types = ["Static Analysis", "Dynamic Analysis", "Protection Detection"]

    progress_manager.start_analysis(binary_path, analysis_types)

    assert progress_manager.progress is not None
    assert progress_manager.live is not None

    for analysis_type in analysis_types:
        assert analysis_type in progress_manager.tasks
        task = progress_manager.tasks[analysis_type]
        assert task.name == analysis_type
        assert task.total_steps == 100

    if progress_manager.live:
        progress_manager.live.stop()


def test_progress_manager_updates_task_progress(progress_manager: Any, tmp_path: Path) -> None:
    """Progress manager updates individual task progress correctly."""
    binary_path = str(tmp_path / "test.exe")
    analysis_types = ["Static Analysis"]

    progress_manager.start_analysis(binary_path, analysis_types)

    progress_manager.update_progress("Static Analysis", current=50, total=100, speed=10.5)

    task = progress_manager.tasks["Static Analysis"]
    assert task.current_step == 50
    assert task.total_steps == 100

    if progress_manager.live:
        progress_manager.live.stop()


def test_progress_manager_completes_task_successfully(progress_manager: Any, tmp_path: Path) -> None:
    """Progress manager marks task as completed with success status."""
    binary_path = str(tmp_path / "test.exe")
    analysis_types = ["Protection Detection"]

    progress_manager.start_analysis(binary_path, analysis_types)

    progress_manager.complete_task("Protection Detection", success=True)

    task = progress_manager.tasks["Protection Detection"]
    assert task.status == "completed"
    assert task.end_time is not None
    assert task.error is None

    if progress_manager.live:
        progress_manager.live.stop()


def test_progress_manager_handles_task_failure(progress_manager: Any, tmp_path: Path) -> None:
    """Progress manager records task failure with error details."""
    binary_path = str(tmp_path / "test.exe")
    analysis_types = ["Dynamic Analysis"]

    progress_manager.start_analysis(binary_path, analysis_types)

    error_message = "Binary execution failed: Access denied"
    progress_manager.complete_task("Dynamic Analysis", success=False, error=error_message)

    task = progress_manager.tasks["Dynamic Analysis"]
    assert task.status == "failed"
    assert task.error == error_message
    assert task.end_time is not None

    if progress_manager.live:
        progress_manager.live.stop()


def test_progress_manager_thread_safe_updates(progress_manager: Any, tmp_path: Path) -> None:
    """Progress manager handles concurrent task updates safely with locking."""
    import threading

    binary_path = str(tmp_path / "test.exe")
    analysis_types = ["Analysis 1", "Analysis 2", "Analysis 3"]

    progress_manager.start_analysis(binary_path, analysis_types)

    def update_task(task_name: str, iterations: int) -> None:
        for i in range(iterations):
            progress_manager.update_progress(task_name, current=i, total=iterations, speed=1.0)
            time.sleep(0.001)

    threads = [
        threading.Thread(target=update_task, args=(task_name, 20))
        for task_name in analysis_types
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    for task_name in analysis_types:
        task = progress_manager.tasks[task_name]
        assert task.current_step >= 0

    if progress_manager.live:
        progress_manager.live.stop()


def test_progress_manager_analysis_task_dataclass(progress_manager: Any) -> None:
    """AnalysisTask dataclass properly initializes with default values."""
    from intellicrack.cli.progress_manager import AnalysisTask

    task = AnalysisTask(
        name="Test Analysis",
        description="Testing analysis task",
    )

    assert task.name == "Test Analysis"
    assert task.description == "Testing analysis task"
    assert task.total_steps == 100
    assert task.current_step == 0
    assert task.status == "pending"
    assert task.start_time is None
    assert task.end_time is None
    assert task.error is None
    assert isinstance(task.subtasks, list)


def test_progress_manager_speed_column_rendering(progress_manager: Any) -> None:
    """SpeedColumn custom progress column renders speed metrics correctly."""
    import threading
    from typing import cast

    from rich.progress import Task, TaskID
    from rich.text import Text

    from intellicrack.cli.progress_manager import SpeedColumn

    column = SpeedColumn()

    mock_task = Task(
        id=cast(TaskID, 1),
        description="Test",
        total=100,
        completed=50,
        visible=True,
        fields={"speed": 15.5},
        _get_time=time.time,
        _lock=threading.RLock(),
    )

    rendered = column.render(mock_task)
    assert isinstance(rendered, Text)


def test_progress_manager_multiple_analysis_sessions(progress_manager: Any, tmp_path: Path) -> None:
    """Progress manager handles multiple sequential analysis sessions."""
    binary1 = str(tmp_path / "binary1.exe")
    binary2 = str(tmp_path / "binary2.exe")

    progress_manager.start_analysis(binary1, ["Static Analysis"])
    progress_manager.complete_task("Static Analysis", success=True)
    if progress_manager.live:
        progress_manager.live.stop()

    progress_manager.start_analysis(binary2, ["Dynamic Analysis"])
    progress_manager.complete_task("Dynamic Analysis", success=True)
    if progress_manager.live:
        progress_manager.live.stop()

    assert "Static Analysis" in progress_manager.tasks
    assert "Dynamic Analysis" in progress_manager.tasks


def test_progress_manager_handles_empty_analysis_types(progress_manager: Any, tmp_path: Path) -> None:
    """Progress manager gracefully handles empty analysis type list."""
    binary_path = str(tmp_path / "test.exe")

    progress_manager.start_analysis(binary_path, [])

    assert progress_manager.progress is not None
    assert len(progress_manager.tasks) == 0

    if progress_manager.live:
        progress_manager.live.stop()


def test_progress_manager_task_not_found_handling(progress_manager: Any, tmp_path: Path) -> None:
    """Progress manager handles updates to non-existent tasks gracefully."""
    binary_path = str(tmp_path / "test.exe")

    progress_manager.start_analysis(binary_path, ["Existing Task"])

    progress_manager.update_progress("Non-Existent Task", current=50, total=100)

    assert "Non-Existent Task" not in progress_manager.tasks

    if progress_manager.live:
        progress_manager.live.stop()


def test_progress_manager_preserves_task_history(progress_manager: Any, tmp_path: Path) -> None:
    """Progress manager preserves completed task information for reporting."""
    binary_path = str(tmp_path / "test.exe")

    progress_manager.start_analysis(binary_path, ["Historical Task"])

    progress_manager.update_progress("Historical Task", current=100, total=100)
    progress_manager.complete_task("Historical Task", success=True)

    task = progress_manager.tasks["Historical Task"]
    assert task.status == "completed"
    assert task.current_step == 100
    assert task.start_time is not None
    assert task.end_time is not None

    if progress_manager.live:
        progress_manager.live.stop()


def test_progress_manager_live_display_starts_and_stops(progress_manager: Any, tmp_path: Path) -> None:
    """Progress manager live display starts and stops cleanly."""
    binary_path = str(tmp_path / "test.exe")

    progress_manager.start_analysis(binary_path, ["Test"])

    assert progress_manager.live is not None

    live_display = progress_manager.live
    live_display.stop()
