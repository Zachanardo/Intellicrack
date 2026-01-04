"""Production tests for UI utilities - validates real UI helper functions.

Tests verify UI utility functions including ProgressTracker, message display,
user input handling, table formatting, and UI update queuing mechanisms.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any, Callable

import pytest

from intellicrack.utils.ui.ui_utils import (
    MessageType,
    ProgressTracker,
    UIUpdateQueue,
    confirm_action,
    create_status_bar_message,
    format_table_data,
    get_user_input,
    select_from_list,
    show_message,
    update_progress,
)


class FakeParentWidget:
    """Real test double for parent widget with message/input history."""

    def __init__(self, class_name: str = "TestWidget") -> None:
        self.__class__.__name__ = class_name
        self.message_history: list[dict[str, Any]] = []
        self.input_history: list[dict[str, Any]] = []


class FakeInputFunction:
    """Real test double for builtins.input function."""

    def __init__(self, responses: list[str | BaseException]) -> None:
        self.responses = responses
        self.call_index = 0
        self.prompts: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        self.prompts.append(prompt)
        if self.call_index >= len(self.responses):
            raise RuntimeError("FakeInputFunction: No more responses available")

        response = self.responses[self.call_index]
        self.call_index += 1

        if isinstance(response, BaseException):
            raise response
        return response


class TestMessageType:
    """Test MessageType enumeration."""

    def test_message_type_values(self) -> None:
        """Verify message type enum has expected values."""
        assert MessageType.INFO.value == "info"
        assert MessageType.WARNING.value == "warning"
        assert MessageType.ERROR.value == "error"
        assert MessageType.SUCCESS.value == "success"
        assert MessageType.DEBUG.value == "debug"

    def test_message_types_are_unique(self) -> None:
        """Test all message types have unique values."""
        values = [mt.value for mt in MessageType]
        assert len(values) == len(set(values))


class TestProgressTracker:
    """Test ProgressTracker with real progress monitoring."""

    def test_tracker_initialization(self) -> None:
        """Verify tracker initializes with correct defaults."""
        tracker = ProgressTracker(total=100)

        assert tracker.total == 100
        assert tracker.current == 0
        assert tracker.is_cancelled is False
        assert tracker.callback is None

    def test_tracker_with_callback(self) -> None:
        """Test tracker calls callback on updates."""
        callback_values: list[int] = []

        def callback(value: int) -> None:
            callback_values.append(value)

        tracker = ProgressTracker(total=100, callback=callback)
        tracker.update(value=25)
        tracker.update(value=50)
        tracker.update(value=75)

        assert callback_values == [25, 50, 75]

    def test_update_with_value(self) -> None:
        """Test updating progress with absolute value."""
        tracker = ProgressTracker(total=100)

        tracker.update(value=45)
        assert tracker.current == 45
        assert tracker.get_percentage() == 45

    def test_update_with_increment(self) -> None:
        """Test updating progress with increment."""
        tracker = ProgressTracker(total=100)

        tracker.update(increment=20)
        assert tracker.current == 20

        tracker.update(increment=15)
        assert tracker.current == 35

    def test_update_respects_maximum(self) -> None:
        """Test updates do not exceed total."""
        tracker = ProgressTracker(total=100)

        tracker.update(value=150)
        assert tracker.current == 100

        tracker.update(value=0)
        tracker.update(increment=120)
        assert tracker.current == 100

    def test_get_percentage_calculation(self) -> None:
        """Test percentage calculation accuracy."""
        tracker = ProgressTracker(total=200)

        tracker.update(value=50)
        assert tracker.get_percentage() == 25

        tracker.update(value=100)
        assert tracker.get_percentage() == 50

        tracker.update(value=200)
        assert tracker.get_percentage() == 100

    def test_get_percentage_zero_total(self) -> None:
        """Test percentage with zero total returns 100."""
        tracker = ProgressTracker(total=0)
        assert tracker.get_percentage() == 100

    def test_cancel_stops_updates(self) -> None:
        """Test cancel prevents further updates."""
        callback_count = 0

        def callback(value: int) -> None:
            nonlocal callback_count
            callback_count += 1

        tracker = ProgressTracker(total=100, callback=callback)

        tracker.update(value=25)
        assert callback_count == 1

        tracker.cancel()
        tracker.update(value=50)

        assert callback_count == 1
        assert tracker.is_cancelled is True

    def test_reset_clears_progress(self) -> None:
        """Test reset clears progress and cancellation state."""
        tracker = ProgressTracker(total=100)

        tracker.update(value=75)
        tracker.cancel()

        tracker.reset()

        assert tracker.current == 0
        assert tracker.is_cancelled is False
        assert tracker.get_percentage() == 0


class TestShowMessage:
    """Test show_message function."""

    def test_show_message_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test showing info message logs correctly."""
        show_message("Test info message", MessageType.INFO)

        assert "Test info message" in caplog.text
        assert "Info" in caplog.text

    def test_show_message_error(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test error messages use error logging level."""
        show_message("Test error", MessageType.ERROR, "Error Title")

        assert "Test error" in caplog.text

    def test_show_message_with_parent(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test message display includes parent context."""
        parent = FakeParentWidget("TestWidget")

        show_message("Message with parent", MessageType.INFO, parent=parent)

        assert "TestWidget" in caplog.text

    def test_show_message_stores_in_parent_history(self) -> None:
        """Test message is stored in parent history if available."""
        parent = FakeParentWidget()

        show_message("Historical message", MessageType.WARNING, "Test", parent)

        assert len(parent.message_history) == 1
        assert parent.message_history[0]["type"] == "warning"
        assert parent.message_history[0]["message"] == "Historical message"


class TestGetUserInput:
    """Test get_user_input function."""

    def test_get_user_input_with_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test getting user input returns sanitized response."""
        fake_input = FakeInputFunction(["test response"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = get_user_input("Enter value")

        assert result == "test response"

    def test_get_user_input_with_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test empty input returns default value."""
        fake_input = FakeInputFunction([""])
        monkeypatch.setattr("builtins.input", fake_input)

        result = get_user_input("Enter value", default="default_value")

        assert result == "default_value"

    def test_get_user_input_sanitizes_newlines(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test input sanitization removes dangerous characters."""
        fake_input = FakeInputFunction(["test\nvalue\rwith\0nulls"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = get_user_input("Enter value")
        assert result is not None

        assert "\n" not in result
        assert "\r" not in result
        assert "\0" not in result

    def test_get_user_input_with_parent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test input with parent stores in history."""
        parent = FakeParentWidget("TestParent")
        fake_input = FakeInputFunction(["test"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = get_user_input("Test prompt", parent=parent)

        assert len(parent.input_history) == 1
        assert parent.input_history[0]["result"] == "test"

    def test_get_user_input_keyboard_interrupt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test keyboard interrupt returns None."""
        fake_input = FakeInputFunction([KeyboardInterrupt()])
        monkeypatch.setattr("builtins.input", fake_input)

        result = get_user_input("Enter value")

        assert result is None

    def test_get_user_input_eof_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test EOF error returns None."""
        fake_input = FakeInputFunction([EOFError()])
        monkeypatch.setattr("builtins.input", fake_input)

        result = get_user_input("Enter value")

        assert result is None


class TestUpdateProgress:
    """Test update_progress function."""

    def test_update_progress_with_callback(self) -> None:
        """Test progress update calls callback function."""
        callback_args: list[tuple[int, str | None]] = []

        def callback(progress: int, message: str | None) -> None:
            callback_args.append((progress, message))

        update_progress(50, "Half complete", callback)

        assert len(callback_args) == 1
        assert callback_args[0] == (50, "Half complete")

    def test_update_progress_logs_with_message(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test progress logging includes message."""
        update_progress(75, "Almost done")

        assert "75%" in caplog.text
        assert "Almost done" in caplog.text

    def test_update_progress_logs_without_message(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test progress logging works without message."""
        update_progress(100)

        assert "100%" in caplog.text


class TestConfirmAction:
    """Test confirm_action function."""

    def test_confirm_action_yes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test confirmation returns True for yes."""
        fake_input = FakeInputFunction(["y"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = confirm_action("Proceed?")

        assert result is True

    def test_confirm_action_yes_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test confirmation accepts 'yes'."""
        fake_input = FakeInputFunction(["yes"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = confirm_action("Proceed?")

        assert result is True

    def test_confirm_action_no(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test confirmation returns False for no."""
        fake_input = FakeInputFunction(["n"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = confirm_action("Proceed?")

        assert result is False

    def test_confirm_action_invalid_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test invalid input returns False."""
        fake_input = FakeInputFunction(["maybe"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = confirm_action("Proceed?")

        assert result is False

    def test_confirm_action_keyboard_interrupt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test keyboard interrupt returns False."""
        fake_input = FakeInputFunction([KeyboardInterrupt()])
        monkeypatch.setattr("builtins.input", fake_input)

        result = confirm_action("Proceed?")

        assert result is False


class TestSelectFromList:
    """Test select_from_list function."""

    def test_select_single_item(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test selecting single item from list."""
        items = ["Option 1", "Option 2", "Option 3"]
        fake_input = FakeInputFunction(["2"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = select_from_list(items)

        assert result == ["Option 2"]

    def test_select_multiple_items(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test selecting multiple items."""
        items = ["A", "B", "C", "D"]
        fake_input = FakeInputFunction(["1,3,4"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = select_from_list(items, allow_multiple=True)

        assert result == ["A", "C", "D"]

    def test_select_all_items(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test selecting all items with 'all' keyword."""
        items = ["X", "Y", "Z"]
        fake_input = FakeInputFunction(["all"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = select_from_list(items, allow_multiple=True)

        assert result == items

    def test_select_empty_list(self) -> None:
        """Test selecting from empty list returns None."""
        result = select_from_list([])

        assert result is None

    def test_select_invalid_index(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test invalid index returns None."""
        items = ["A", "B", "C"]
        fake_input = FakeInputFunction(["10"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = select_from_list(items)

        assert result is None

    def test_select_non_numeric_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test non-numeric input returns None."""
        items = ["A", "B", "C"]
        fake_input = FakeInputFunction(["abc"])
        monkeypatch.setattr("builtins.input", fake_input)

        result = select_from_list(items)

        assert result is None

    def test_select_keyboard_interrupt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test keyboard interrupt returns None."""
        items = ["A", "B"]
        fake_input = FakeInputFunction([KeyboardInterrupt()])
        monkeypatch.setattr("builtins.input", fake_input)

        result = select_from_list(items)

        assert result is None


class TestCreateStatusBarMessage:
    """Test create_status_bar_message function."""

    def test_creates_message_configuration(self) -> None:
        """Test creating status bar message configuration."""
        config = create_status_bar_message("Test message", timeout=3000)

        assert config["message"] == "Test message"
        assert config["timeout"] == 3000
        assert config["timestamp"] is None

    def test_default_timeout(self) -> None:
        """Test default timeout is 5000ms."""
        config = create_status_bar_message("Message")

        assert config["timeout"] == 5000


class TestFormatTableData:
    """Test format_table_data function."""

    def test_format_simple_table(self) -> None:
        """Test formatting simple table data."""
        headers = ["Name", "Age", "City"]
        rows = [
            ["Alice", 30, "New York"],
            ["Bob", 25, "London"],
            ["Charlie", 35, "Paris"],
        ]

        result = format_table_data(headers, rows)

        assert "Name" in result
        assert "Age" in result
        assert "Alice" in result
        assert "Bob" in result
        assert "|" in result
        assert "-" in result

    def test_format_empty_table(self) -> None:
        """Test formatting empty table returns empty string."""
        result = format_table_data([], [])

        assert result == ""

    def test_format_table_respects_max_width(self) -> None:
        """Test table formatting respects maximum width."""
        headers = ["Very Long Header Name", "Another Long Header"]
        rows = [
            ["Very long content that exceeds width", "More long content here"],
        ]

        result = format_table_data(headers, rows, max_width=50)  # type: ignore[arg-type]

        lines = result.split("\n")
        for line in lines:
            assert len(line) <= 60

    def test_format_table_alignment(self) -> None:
        """Test table formatting aligns columns properly."""
        headers = ["A", "B", "C"]
        rows = [
            ["Short", "Medium text", "Very long content"],
            ["X", "Y", "Z"],
        ]

        result = format_table_data(headers, rows)  # type: ignore[arg-type]

        lines = result.split("\n")
        assert len(lines) >= 4


class TestUIUpdateQueue:
    """Test UIUpdateQueue for batching UI updates."""

    def test_queue_initialization(self) -> None:
        """Verify queue initializes empty."""
        queue = UIUpdateQueue()

        assert queue.updates == []

    def test_add_update_appends_to_queue(self) -> None:
        """Test adding updates to queue."""
        queue = UIUpdateQueue()

        queue.add_update("type1", {"data": 1})
        queue.add_update("type2", {"data": 2})

        assert len(queue.updates) == 2
        assert queue.updates[0] == ("type1", {"data": 1})
        assert queue.updates[1] == ("type2", {"data": 2})

    def test_flush_processes_all_updates(self) -> None:
        """Test flushing queue processes all updates."""
        queue = UIUpdateQueue()
        processed: list[tuple[str, Any]] = []

        def callback(update_type: str, data: Any) -> None:
            processed.append((update_type, data))

        queue.add_update("update1", "data1")
        queue.add_update("update2", "data2")
        queue.add_update("update3", "data3")

        queue.flush(callback)

        assert len(processed) == 3
        assert processed[0] == ("update1", "data1")
        assert processed[1] == ("update2", "data2")
        assert processed[2] == ("update3", "data3")
        assert queue.updates == []

    def test_clear_removes_all_updates(self) -> None:
        """Test clearing queue removes all updates."""
        queue = UIUpdateQueue()

        queue.add_update("type1", "data1")
        queue.add_update("type2", "data2")

        assert len(queue.updates) == 2

        queue.clear()

        assert queue.updates == []

    def test_flush_on_empty_queue(self) -> None:
        """Test flushing empty queue doesn't call callback."""
        queue = UIUpdateQueue()
        callback_called = False

        def callback(update_type: str, data: Any) -> None:
            nonlocal callback_called
            callback_called = True

        queue.flush(callback)

        assert not callback_called


@pytest.mark.integration
class TestUIUtilsIntegration:
    """Integration tests for UI utility functions."""

    def test_progress_tracker_workflow(self) -> None:
        """Test complete progress tracking workflow."""
        progress_updates: list[int] = []

        def track_progress(value: int) -> None:
            progress_updates.append(value)

        tracker = ProgressTracker(total=100, callback=track_progress)

        for i in range(0, 101, 10):
            tracker.update(value=i)

        assert len(progress_updates) == 11
        assert progress_updates[-1] == 100

    def test_update_queue_batch_processing(self) -> None:
        """Test batch processing of UI updates."""
        queue = UIUpdateQueue()
        results: list[str] = []

        def process_update(update_type: str, data: Any) -> None:
            results.append(f"{update_type}: {data}")

        for i in range(10):
            queue.add_update(f"update_{i}", f"value_{i}")

        assert len(queue.updates) == 10

        queue.flush(process_update)

        assert len(results) == 10
        assert len(queue.updates) == 0

    def test_table_formatting_with_real_data(self) -> None:
        """Test table formatting with realistic protection analysis data."""
        headers = ["Binary", "Protection", "Status"]
        rows = [
            ["notepad.exe", "None", "Clean"],
            ["protected_app.exe", "VMProtect 3.5", "Detected"],
            ["game.exe", "Themida 3.1", "Detected"],
            ["software.exe", "Enigma 6.7", "Detected"],
        ]

        result = format_table_data(headers, rows)  # type: ignore[arg-type]

        assert "notepad.exe" in result
        assert "VMProtect" in result
        assert "Detected" in result

        lines = result.split("\n")
        assert len(lines) >= 6
