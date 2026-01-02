"""Production tests for log message utility.

Tests validate that the enhanced logging system works correctly with UI
integration, message categorization, context tracking, and callback notifications
for real-time display in the Intellicrack GUI.
"""

import threading
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from intellicrack.utils.log_message import (
    MessageCategory,
    MessageLevel,
    clear_message_queue,
    get_message_queue,
    log_analysis,
    log_binary_processing,
    log_critical,
    log_debug,
    log_error,
    log_info,
    log_message,
    log_msg,
    log_performance,
    log_security,
    log_ui,
    log_warning,
    message_log,
    register_message_callback,
    unregister_message_callback,
)


class FakeLogger:
    """Real test double for logging.Logger."""

    def __init__(self) -> None:
        self.log_calls: List[Tuple[int, str, Dict[str, Any]]] = []
        self.should_fail: bool = False

    def log(self, level: int, message: str, **kwargs: Any) -> None:
        """Record log call with level, message, and extras."""
        if self.should_fail:
            raise Exception("Logging error")
        self.log_calls.append((level, message, kwargs))

    def reset(self) -> None:
        """Clear recorded calls."""
        self.log_calls.clear()
        self.should_fail = False

    def get_last_call(self) -> Optional[Tuple[int, str, Dict[str, Any]]]:
        """Get most recent log call."""
        return self.log_calls[-1] if self.log_calls else None

    def get_all_calls(self) -> List[Tuple[int, str, Dict[str, Any]]]:
        """Get all log calls."""
        return self.log_calls.copy()


@pytest.fixture
def fake_logger(monkeypatch: pytest.MonkeyPatch) -> FakeLogger:
    """Provide fake logger and inject it into log_message module."""
    logger = FakeLogger()
    monkeypatch.setattr("intellicrack.utils.log_message.main_logger", logger)
    return logger


class TestMessageLevelEnum:
    """Test MessageLevel enumeration."""

    def test_has_all_severity_levels(self) -> None:
        """MessageLevel enum contains all standard severity levels."""
        assert hasattr(MessageLevel, "DEBUG")
        assert hasattr(MessageLevel, "INFO")
        assert hasattr(MessageLevel, "WARNING")
        assert hasattr(MessageLevel, "ERROR")
        assert hasattr(MessageLevel, "CRITICAL")

    def test_level_values_are_strings(self) -> None:
        """MessageLevel values are uppercase strings."""
        assert MessageLevel.DEBUG.value == "DEBUG"
        assert MessageLevel.INFO.value == "INFO"
        assert MessageLevel.WARNING.value == "WARNING"
        assert MessageLevel.ERROR.value == "ERROR"
        assert MessageLevel.CRITICAL.value == "CRITICAL"


class TestMessageCategoryEnum:
    """Test MessageCategory enumeration."""

    def test_has_common_categories(self) -> None:
        """MessageCategory enum contains common message categories."""
        assert hasattr(MessageCategory, "GENERAL")
        assert hasattr(MessageCategory, "ANALYSIS")
        assert hasattr(MessageCategory, "UI")
        assert hasattr(MessageCategory, "SECURITY")
        assert hasattr(MessageCategory, "PERFORMANCE")

    def test_has_technical_categories(self) -> None:
        """MessageCategory enum contains technical categories."""
        assert hasattr(MessageCategory, "NETWORK")
        assert hasattr(MessageCategory, "FILE_IO")
        assert hasattr(MessageCategory, "BINARY_PROCESSING")


class TestLogMessage:
    """Test core log_message functionality."""

    def test_logs_basic_message(self, fake_logger: FakeLogger) -> None:
        """log_message logs basic message at INFO level."""
        log_message("Test message")

        assert len(fake_logger.log_calls) == 1
        level, message, kwargs = fake_logger.get_last_call()
        assert "Test message" in message

    def test_accepts_string_level(self, fake_logger: FakeLogger) -> None:
        """log_message accepts string level parameter."""
        log_message("Test", level="ERROR")
        assert len(fake_logger.log_calls) == 1

    def test_accepts_enum_level(self, fake_logger: FakeLogger) -> None:
        """log_message accepts MessageLevel enum."""
        log_message("Test", level=MessageLevel.WARNING)
        assert len(fake_logger.log_calls) == 1

    def test_accepts_string_category(self, fake_logger: FakeLogger) -> None:
        """log_message accepts string category parameter."""
        log_message("Test", category="ANALYSIS")
        assert len(fake_logger.log_calls) == 1

    def test_accepts_enum_category(self, fake_logger: FakeLogger) -> None:
        """log_message accepts MessageCategory enum."""
        log_message("Test", category=MessageCategory.SECURITY)
        assert len(fake_logger.log_calls) == 1

    def test_includes_context_in_message(self, fake_logger: FakeLogger) -> None:
        """log_message includes context dictionary in message."""
        log_message(
            "Test",
            context={"key1": "value1", "key2": 42},
        )

        level, message, kwargs = fake_logger.get_last_call()
        assert "Context:" in message
        assert "key1=value1" in message or "key2=42" in message

    def test_includes_source_in_message(self, fake_logger: FakeLogger) -> None:
        """log_message includes source identifier in message."""
        log_message("Test", source="test_module.test_function")

        level, message, kwargs = fake_logger.get_last_call()
        assert "Source:" in message
        assert "test_module.test_function" in message

    def test_includes_exception_in_message(self, fake_logger: FakeLogger) -> None:
        """log_message includes exception information in message."""
        test_exception = ValueError("Test error")

        log_message("Test", exception=test_exception)

        level, message, kwargs = fake_logger.get_last_call()
        assert "Exception:" in message
        assert "ValueError" in message

    def test_uses_custom_timestamp(self, fake_logger: FakeLogger) -> None:
        """log_message accepts custom timestamp."""
        custom_time = datetime(2025, 1, 1, 12, 0, 0)

        clear_message_queue()
        log_message("Test", timestamp=custom_time)

        queue = get_message_queue()
        assert len(queue) == 1
        assert "2025-01-01" in queue[0]["timestamp"]


class TestMessageQueueManagement:
    """Test message queue functionality."""

    def test_message_added_to_queue_when_persist_true(
        self, fake_logger: FakeLogger
    ) -> None:
        """Messages are added to queue when persist=True."""
        clear_message_queue()

        log_message("Test message", persist=True)

        queue = get_message_queue()
        assert len(queue) == 1
        assert queue[0]["message"] == "Test message"

    def test_message_not_added_to_queue_when_persist_false(
        self, fake_logger: FakeLogger
    ) -> None:
        """Messages are not added to queue when persist=False."""
        clear_message_queue()

        log_message("Test message", persist=False)

        queue = get_message_queue()
        assert len(queue) == 0

    def test_queue_stores_complete_message_info(self, fake_logger: FakeLogger) -> None:
        """Message queue stores complete message information."""
        clear_message_queue()

        log_message(
            "Test",
            level=MessageLevel.ERROR,
            category=MessageCategory.ANALYSIS,
            context={"key": "value"},
            source="test_source",
        )

        queue = get_message_queue()
        entry = queue[0]

        assert entry["level"] == "ERROR"
        assert entry["category"] == "ANALYSIS"
        assert entry["message"] == "Test"
        assert entry["context"] == {"key": "value"}
        assert entry["source"] == "test_source"

    def test_queue_limits_size_to_prevent_memory_issues(
        self, fake_logger: FakeLogger
    ) -> None:
        """Message queue limits size to prevent memory issues."""
        clear_message_queue()

        for i in range(1100):
            log_message(f"Message {i}")

        queue = get_message_queue()
        assert len(queue) <= 1000

    def test_clear_message_queue_empties_queue(self, fake_logger: FakeLogger) -> None:
        """clear_message_queue removes all messages from queue."""
        log_message("Message 1")
        log_message("Message 2")

        clear_message_queue()
        queue = get_message_queue()

        assert len(queue) == 0

    def test_get_message_queue_returns_copy(self, fake_logger: FakeLogger) -> None:
        """get_message_queue returns a copy, not the original queue."""
        clear_message_queue()

        log_message("Test")

        queue1 = get_message_queue()
        queue2 = get_message_queue()

        assert queue1 is not queue2
        assert queue1 == queue2


class TestCallbackManagement:
    """Test message callback registration and notification."""

    def test_register_callback_adds_callback(self) -> None:
        """register_message_callback adds callback to list."""

        def test_callback(level: str, category: str, message: str) -> None:
            pass

        register_message_callback(test_callback)
        unregister_message_callback(test_callback)

    def test_callback_receives_notifications(self, fake_logger: FakeLogger) -> None:
        """Registered callback receives message notifications."""
        callback_data: List[Tuple[str, str, str]] = []

        def test_callback(level: str, category: str, message: str) -> None:
            callback_data.append((level, category, message))

        register_message_callback(test_callback)

        try:
            log_message(
                "Test message",
                level=MessageLevel.WARNING,
                category=MessageCategory.SECURITY,
            )

            assert len(callback_data) == 1
            assert callback_data[0][0] == "WARNING"
            assert callback_data[0][1] == "SECURITY"
            assert "Test message" in callback_data[0][2]
        finally:
            unregister_message_callback(test_callback)

    def test_unregister_callback_removes_callback(
        self, fake_logger: FakeLogger
    ) -> None:
        """unregister_message_callback removes callback from list."""
        callback_data: List[Tuple[str, str, str]] = []

        def test_callback(level: str, category: str, message: str) -> None:
            callback_data.append((level, category, message))

        register_message_callback(test_callback)
        unregister_message_callback(test_callback)

        log_message("Test after unregister")

        assert not callback_data

    def test_callback_not_added_twice(self, fake_logger: FakeLogger) -> None:
        """Callback is not added multiple times."""
        call_count: int = 0

        def test_callback(level: str, category: str, message: str) -> None:
            nonlocal call_count
            call_count += 1

        register_message_callback(test_callback)
        register_message_callback(test_callback)

        try:
            log_message("Test")

            assert call_count == 1
        finally:
            unregister_message_callback(test_callback)

    def test_callback_errors_do_not_break_logging(
        self, fake_logger: FakeLogger
    ) -> None:
        """Errors in callbacks do not prevent logging."""

        def failing_callback(level: str, category: str, message: str) -> None:
            raise RuntimeError("Callback error")

        register_message_callback(failing_callback)

        try:
            log_message("Test message")
        finally:
            unregister_message_callback(failing_callback)

    def test_messages_not_sent_to_callbacks_when_notify_false(
        self, fake_logger: FakeLogger
    ) -> None:
        """Messages are not sent to callbacks when notify_ui=False."""
        callback_data: List[str] = []

        def test_callback(level: str, category: str, message: str) -> None:
            callback_data.append(message)

        register_message_callback(test_callback)

        try:
            log_message("Test", notify_ui=False)

            assert not callback_data
        finally:
            unregister_message_callback(test_callback)


class TestConvenienceFunctions:
    """Test convenience logging functions."""

    def test_log_debug_logs_at_debug_level(self, fake_logger: FakeLogger) -> None:
        """log_debug logs message at DEBUG level."""
        clear_message_queue()

        log_debug("Debug message")

        queue = get_message_queue()
        assert queue[0]["level"] == "DEBUG"

    def test_log_info_logs_at_info_level(self, fake_logger: FakeLogger) -> None:
        """log_info logs message at INFO level."""
        clear_message_queue()

        log_info("Info message")

        queue = get_message_queue()
        assert queue[0]["level"] == "INFO"

    def test_log_warning_logs_at_warning_level(self, fake_logger: FakeLogger) -> None:
        """log_warning logs message at WARNING level."""
        clear_message_queue()

        log_warning("Warning message")

        queue = get_message_queue()
        assert queue[0]["level"] == "WARNING"

    def test_log_error_logs_at_error_level(self, fake_logger: FakeLogger) -> None:
        """log_error logs message at ERROR level."""
        clear_message_queue()

        log_error("Error message")

        queue = get_message_queue()
        assert queue[0]["level"] == "ERROR"

    def test_log_critical_logs_at_critical_level(self, fake_logger: FakeLogger) -> None:
        """log_critical logs message at CRITICAL level."""
        clear_message_queue()

        log_critical("Critical message")

        queue = get_message_queue()
        assert queue[0]["level"] == "CRITICAL"


class TestCategorySpecificFunctions:
    """Test category-specific logging functions."""

    def test_log_analysis_uses_analysis_category(
        self, fake_logger: FakeLogger
    ) -> None:
        """log_analysis logs with ANALYSIS category."""
        clear_message_queue()

        log_analysis("Analysis message")

        queue = get_message_queue()
        assert queue[0]["category"] == "ANALYSIS"

    def test_log_ui_uses_ui_category(self, fake_logger: FakeLogger) -> None:
        """log_ui logs with UI category."""
        clear_message_queue()

        log_ui("UI message")

        queue = get_message_queue()
        assert queue[0]["category"] == "UI"

    def test_log_security_uses_security_category(self, fake_logger: FakeLogger) -> None:
        """log_security logs with SECURITY category."""
        clear_message_queue()

        log_security("Security message")

        queue = get_message_queue()
        assert queue[0]["category"] == "SECURITY"

    def test_log_performance_uses_performance_category(
        self, fake_logger: FakeLogger
    ) -> None:
        """log_performance logs with PERFORMANCE category."""
        clear_message_queue()

        log_performance("Performance message")

        queue = get_message_queue()
        assert queue[0]["category"] == "PERFORMANCE"

    def test_log_binary_processing_uses_binary_processing_category(
        self, fake_logger: FakeLogger
    ) -> None:
        """log_binary_processing logs with BINARY_PROCESSING category."""
        clear_message_queue()

        log_binary_processing("Binary message")

        queue = get_message_queue()
        assert queue[0]["category"] == "BINARY_PROCESSING"

    def test_category_functions_accept_custom_level(
        self, fake_logger: FakeLogger
    ) -> None:
        """Category-specific functions accept custom level parameter."""
        clear_message_queue()

        log_analysis("Test", level=MessageLevel.ERROR)

        queue = get_message_queue()
        assert queue[0]["level"] == "ERROR"
        assert queue[0]["category"] == "ANALYSIS"


class TestLegacyAliases:
    """Test legacy compatibility aliases."""

    def test_log_msg_works_as_alias(self, fake_logger: FakeLogger) -> None:
        """log_msg works as legacy alias for log_message."""
        clear_message_queue()

        log_msg("Legacy message")

        queue = get_message_queue()
        assert len(queue) == 1
        assert queue[0]["message"] == "Legacy message"

    def test_message_log_works_as_alias(self, fake_logger: FakeLogger) -> None:
        """message_log works as legacy alias for log_message."""
        clear_message_queue()

        message_log("Legacy message")

        queue = get_message_queue()
        assert len(queue) == 1
        assert queue[0]["message"] == "Legacy message"


class TestThreadSafety:
    """Test thread safety of logging system."""

    def test_message_queue_is_thread_safe(self, fake_logger: FakeLogger) -> None:
        """Message queue operations are thread-safe."""
        clear_message_queue()
        threads: List[threading.Thread] = []

        def log_from_thread(thread_id: int) -> None:
            for i in range(10):
                log_message(f"Thread {thread_id} message {i}")

        for i in range(5):
            thread = threading.Thread(target=log_from_thread, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        queue = get_message_queue()
        assert len(queue) == 50

    def test_callback_registration_is_thread_safe(self) -> None:
        """Callback registration is thread-safe."""
        callbacks: List[Callable[[str, str, str], None]] = []

        def register_from_thread(thread_id: int) -> None:
            def callback(level: str, category: str, message: str) -> None:
                pass

            callbacks.append(callback)
            register_message_callback(callback)

        threads: List[threading.Thread] = []
        for i in range(5):
            thread = threading.Thread(target=register_from_thread, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        for callback in callbacks:
            unregister_message_callback(callback)


class TestRealWorldScenarios:
    """Test realistic production usage scenarios."""

    def test_binary_analysis_logging(self, fake_logger: FakeLogger) -> None:
        """Test logging during binary analysis workflow."""
        clear_message_queue()

        log_analysis("Starting binary analysis", source="binary_analyzer")
        log_binary_processing(
            "Loaded PE file",
            context={"file_size": 1024000, "architecture": "x64"},
        )
        log_security(
            "Found suspicious API calls",
            level=MessageLevel.WARNING,
            context={"apis": ["CreateProcess", "VirtualAlloc"]},
        )
        log_analysis("Analysis complete")

        queue = get_message_queue()
        assert len(queue) == 4
        assert queue[1]["context"]["file_size"] == 1024000

    def test_error_logging_with_exception(self, fake_logger: FakeLogger) -> None:
        """Test error logging with exception information."""
        clear_message_queue()

        try:
            raise ValueError("Invalid license key format")
        except ValueError as e:
            log_error(
                "License validation failed",
                exception=e,
                context={"key": "ABC-123-XYZ"},
            )

            queue = get_message_queue()
            assert queue[0]["exception"] is not None
            assert "ValueError" in queue[0]["exception"]


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_handles_empty_message(self, fake_logger: FakeLogger) -> None:
        """Logging handles empty message string."""
        log_message("")
        assert len(fake_logger.log_calls) == 1

    def test_handles_very_long_message(self, fake_logger: FakeLogger) -> None:
        """Logging handles very long messages."""
        long_message = "A" * 10000

        log_message(long_message)
        assert len(fake_logger.log_calls) == 1

    def test_handles_empty_context(self, fake_logger: FakeLogger) -> None:
        """Logging handles empty context dictionary."""
        log_message("Test", context={})
        assert len(fake_logger.log_calls) == 1

    def test_handles_none_values_in_context(self, fake_logger: FakeLogger) -> None:
        """Logging handles None values in context."""
        log_message("Test", context={"key": None})
        assert len(fake_logger.log_calls) == 1

    def test_handles_complex_context_values(self, fake_logger: FakeLogger) -> None:
        """Logging handles complex objects in context."""
        log_message(
            "Test",
            context={
                "list": [1, 2, 3],
                "dict": {"nested": "value"},
                "tuple": (1, 2),
            },
        )
        assert len(fake_logger.log_calls) == 1

    def test_handles_logging_system_failure(self, fake_logger: FakeLogger) -> None:
        """Logging handles failures in underlying logging system."""
        fake_logger.should_fail = True

        log_message("Test message")
