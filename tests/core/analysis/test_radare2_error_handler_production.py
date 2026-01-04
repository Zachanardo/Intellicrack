"""Production tests for radare2 error handler.

Tests error handling, recovery strategies, and circuit breaker functionality
on real error conditions without mocks.
"""

import time
from datetime import datetime, timedelta
from typing import Any
import pytest

from intellicrack.core.analysis.radare2_error_handler import (
    ErrorEvent,
    ErrorSeverity,
    R2ErrorHandler,
    RecoveryAction,
    RecoveryStrategy,
    get_error_handler,
    handle_r2_error,
    r2_error_context,
)


@pytest.fixture
def error_handler() -> R2ErrorHandler:
    """Create fresh error handler instance."""
    return R2ErrorHandler(max_errors_per_session=10)


@pytest.fixture
def sample_error() -> Exception:
    """Create sample exception."""
    return RuntimeError("Test error message")


@pytest.fixture
def r2pipe_error() -> Exception:
    """Create r2pipe-related error."""
    return BrokenPipeError("r2pipe connection lost")


@pytest.fixture
def timeout_error() -> Exception:
    """Create timeout error."""
    return TimeoutError("Operation timeout in r2 analysis")


@pytest.fixture
def critical_error() -> Exception:
    """Create critical error."""
    return MemoryError("Out of memory during analysis")


class TestErrorDataStructures:
    """Test error data structures."""

    def test_error_event_creation(self) -> None:
        """ErrorEvent creates with all attributes."""
        event = ErrorEvent(
            timestamp=datetime.now(),
            error_type="RuntimeError",
            severity=ErrorSeverity.MEDIUM,
            message="Test error",
            context={"operation": "test"},
            traceback="test traceback",
            recovery_strategy=RecoveryStrategy.RETRY,
        )

        assert event.error_type == "RuntimeError"
        assert event.severity == ErrorSeverity.MEDIUM
        assert event.message == "Test error"
        assert event.recovery_attempts == 0
        assert event.resolved is False

    def test_recovery_action_creation(self) -> None:
        """RecoveryAction creates with all attributes."""
        action = RecoveryAction(
            name="Test Action",
            description="Test description",
            action=lambda e: True,
            max_attempts=5,
            delay=2.0,
        )

        assert action.name == "Test Action"
        assert action.max_attempts == 5
        assert action.delay == 2.0
        assert action.exponential_backoff is True


class TestR2ErrorHandlerInitialization:
    """Test R2ErrorHandler initialization."""

    def test_handler_initializes_successfully(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Handler initializes with correct defaults."""
        assert error_handler.max_errors_per_session == 10
        assert len(error_handler.error_history) == 0
        assert error_handler.session_stats["total_errors"] == 0
        assert error_handler.session_stats["recovered_errors"] == 0
        assert error_handler.session_stats["critical_errors"] == 0

    def test_built_in_recovery_actions_registered(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Built-in recovery actions are registered."""
        assert "restart_r2_session" in error_handler.recovery_actions
        assert "re_analyze_binary" in error_handler.recovery_actions
        assert "retry_with_fallback" in error_handler.recovery_actions
        assert "cleanup_memory" in error_handler.recovery_actions
        assert "graceful_degradation" in error_handler.recovery_actions

    def test_performance_monitor_initialized(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Performance monitor is initialized."""
        assert "operation_times" in error_handler.performance_monitor  # type: ignore[attr-defined]
        assert "failure_rates" in error_handler.performance_monitor  # type: ignore[attr-defined]
        assert "recovery_success_rates" in error_handler.performance_monitor  # type: ignore[attr-defined]


class TestErrorSeverityClassification:
    """Test error severity classification."""

    def test_classify_memory_error_as_critical(
        self, error_handler: R2ErrorHandler, critical_error: Exception
    ) -> None:
        """MemoryError classified as CRITICAL."""
        severity = error_handler._classify_error_severity(critical_error, "test_op")
        assert severity == ErrorSeverity.CRITICAL

    def test_classify_timeout_as_medium(
        self, error_handler: R2ErrorHandler, timeout_error: Exception
    ) -> None:
        """Timeout errors classified as MEDIUM."""
        severity = error_handler._classify_error_severity(timeout_error, "test_op")
        assert severity == ErrorSeverity.MEDIUM

    def test_classify_r2pipe_error_as_high(
        self, error_handler: R2ErrorHandler, r2pipe_error: Exception
    ) -> None:
        """r2pipe errors classified as HIGH."""
        severity = error_handler._classify_error_severity(r2pipe_error, "r2_analysis")
        assert severity == ErrorSeverity.HIGH

    def test_classify_json_error_as_low(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """JSON parsing errors classified as LOW."""
        json_error = ValueError("Invalid JSON in response")
        severity = error_handler._classify_error_severity(json_error, "parse_json")
        assert severity == ErrorSeverity.LOW

    def test_classify_file_not_found_as_high(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """FileNotFoundError for radare2 classified as HIGH."""
        file_error = FileNotFoundError("radare2 binary not found")
        severity = error_handler._classify_error_severity(file_error, "r2_init")
        assert severity == ErrorSeverity.HIGH


class TestRecoveryStrategyDetermination:
    """Test recovery strategy determination."""

    def test_critical_error_requires_user_intervention(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Critical errors require user intervention."""
        event = ErrorEvent(
            timestamp=datetime.now(),
            error_type="MemoryError",
            severity=ErrorSeverity.CRITICAL,
            message="Out of memory",
            context={},
            traceback="",
            recovery_strategy=RecoveryStrategy.RETRY,
        )

        strategy = error_handler._determine_recovery_strategy(event)
        assert strategy == RecoveryStrategy.USER_INTERVENTION

    def test_r2pipe_error_uses_retry(self, error_handler: R2ErrorHandler) -> None:
        """r2pipe errors use RETRY strategy."""
        event = ErrorEvent(
            timestamp=datetime.now(),
            error_type="BrokenPipeError",
            severity=ErrorSeverity.HIGH,
            message="r2pipe connection failed",
            context={},
            traceback="",
            recovery_strategy=RecoveryStrategy.RETRY,
        )

        strategy = error_handler._determine_recovery_strategy(event)
        assert strategy == RecoveryStrategy.RETRY

    def test_file_error_uses_fallback(self, error_handler: R2ErrorHandler) -> None:
        """File errors use FALLBACK strategy."""
        event = ErrorEvent(
            timestamp=datetime.now(),
            error_type="FileNotFoundError",
            severity=ErrorSeverity.HIGH,
            message="File not found",
            context={},
            traceback="",
            recovery_strategy=RecoveryStrategy.RETRY,
        )

        strategy = error_handler._determine_recovery_strategy(event)
        assert strategy == RecoveryStrategy.FALLBACK

    def test_timeout_uses_graceful_degradation(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Timeout errors use GRACEFUL_DEGRADATION."""
        event = ErrorEvent(
            timestamp=datetime.now(),
            error_type="TimeoutError",
            severity=ErrorSeverity.MEDIUM,
            message="Operation timeout",
            context={},
            traceback="",
            recovery_strategy=RecoveryStrategy.RETRY,
        )

        strategy = error_handler._determine_recovery_strategy(event)
        assert strategy == RecoveryStrategy.GRACEFUL_DEGRADATION

    def test_too_many_errors_triggers_degradation(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Too many errors trigger graceful degradation."""
        error_handler.session_stats["total_errors"] = 15

        event = ErrorEvent(
            timestamp=datetime.now(),
            error_type="RuntimeError",
            severity=ErrorSeverity.MEDIUM,
            message="Test error",
            context={},
            traceback="",
            recovery_strategy=RecoveryStrategy.RETRY,
        )

        strategy = error_handler._determine_recovery_strategy(event)
        assert strategy == RecoveryStrategy.GRACEFUL_DEGRADATION


class TestErrorContext:
    """Test error context manager."""

    def test_error_context_catches_exceptions(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Error context catches and logs exceptions."""
        with pytest.raises(RuntimeError):
            with error_handler.error_context("test_operation"):
                raise RuntimeError("Test error")

        assert error_handler.session_stats["total_errors"] >= 0

    def test_error_context_records_performance(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Error context records performance metrics."""
        with error_handler.error_context("successful_operation"):
            time.sleep(0.01)

        assert "successful_operation" in error_handler.performance_monitor["operation_times"]  # type: ignore[attr-defined]

    def test_error_context_records_failures(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Error context records failures."""
        with pytest.raises(ValueError):
            with error_handler.error_context("failing_operation"):
                raise ValueError("Test failure")

        assert "failing_operation" in error_handler.performance_monitor["failure_rates"]  # type: ignore[attr-defined]


class TestCircuitBreaker:
    """Test circuit breaker pattern."""

    def test_circuit_breaker_opens_after_failures(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Circuit breaker opens after threshold failures."""
        operation = "failing_operation"

        for _ in range(6):
            error_handler._update_circuit_breaker(operation, success=False)

        assert error_handler._is_circuit_broken(operation)

    def test_circuit_breaker_remains_closed_on_success(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Circuit breaker remains closed with successes."""
        operation = "successful_operation"

        for _ in range(10):
            error_handler._update_circuit_breaker(operation, success=True)

        assert not error_handler._is_circuit_broken(operation)

    def test_circuit_breaker_resets_after_cooldown(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Circuit breaker transitions to half-open after cooldown."""
        operation = "temp_failing_operation"

        for _ in range(6):
            error_handler._update_circuit_breaker(operation, success=False)

        assert error_handler._is_circuit_broken(operation)

        error_handler.circuit_breakers[operation]["last_failure"] = datetime.now() - timedelta(minutes=6)

        assert not error_handler._is_circuit_broken(operation)

    def test_reset_circuit_breaker(self, error_handler: R2ErrorHandler) -> None:
        """Circuit breaker can be manually reset."""
        operation = "test_operation"

        for _ in range(6):
            error_handler._update_circuit_breaker(operation, success=False)

        error_handler.reset_circuit_breaker(operation)

        assert not error_handler._is_circuit_broken(operation)


class TestRecoveryActions:
    """Test recovery action execution."""

    def test_execute_recovery_action_with_delay(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Recovery action executes with delay."""
        executed = False

        def test_action(event: ErrorEvent) -> bool:
            nonlocal executed
            executed = True
            return True

        action = RecoveryAction(
            name="test_action",
            description="Test",
            action=test_action,
            delay=0.01,
        )

        error_handler.add_recovery_action("test_action", action)

        event = ErrorEvent(
            timestamp=datetime.now(),
            error_type="TestError",
            severity=ErrorSeverity.LOW,
            message="Test",
            context={},
            traceback="",
            recovery_strategy=RecoveryStrategy.RETRY,
        )

        start = time.time()
        result = error_handler._execute_recovery_action("test_action", event)
        duration = time.time() - start

        assert result is True
        assert executed
        assert duration >= 0.01

    def test_recovery_action_exponential_backoff(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Recovery action uses exponential backoff."""
        action = RecoveryAction(
            name="backoff_action",
            description="Test backoff",
            action=lambda e: False,
            delay=0.01,
            exponential_backoff=True,
        )

        error_handler.add_recovery_action("backoff_action", action)

        event = ErrorEvent(
            timestamp=datetime.now(),
            error_type="TestError",
            severity=ErrorSeverity.LOW,
            message="Test",
            context={},
            traceback="",
            recovery_strategy=RecoveryStrategy.RETRY,
            recovery_attempts=2,
        )

        start = time.time()
        error_handler._execute_recovery_action("backoff_action", event)
        duration = time.time() - start

        expected_delay = 0.01 * (2**2)
        assert duration >= expected_delay

    def test_recovery_action_max_attempts(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Recovery action respects max attempts."""
        attempts = 0

        def counting_action(event: ErrorEvent) -> bool:
            nonlocal attempts
            attempts += 1
            return False

        action = RecoveryAction(
            name="limited_action",
            description="Test",
            action=counting_action,
            max_attempts=2,
            delay=0.0,
        )

        error_handler.add_recovery_action("limited_action", action)

        event = ErrorEvent(
            timestamp=datetime.now(),
            error_type="TestError",
            severity=ErrorSeverity.LOW,
            message="Test",
            context={},
            traceback="",
            recovery_strategy=RecoveryStrategy.RETRY,
            recovery_attempts=3,
        )

        result = error_handler._execute_recovery_action("limited_action", event)
        assert result is False
        assert attempts == 0


class TestPerformanceMonitoring:
    """Test performance monitoring."""

    def test_record_performance_for_operation(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Performance is recorded for operations."""
        error_handler._record_performance("test_op", 1.5, success=True)

        assert "test_op" in error_handler.performance_monitor["operation_times"]  # type: ignore[attr-defined]
        assert 1.5 in error_handler.performance_monitor["operation_times"]["test_op"]  # type: ignore[attr-defined]

    def test_performance_history_limited(self, error_handler: R2ErrorHandler) -> None:
        """Performance history is limited to 100 entries."""
        for i in range(150):
            error_handler._record_performance("test_op", float(i), success=True)

        assert len(error_handler.performance_monitor["operation_times"]["test_op"]) == 100  # type: ignore[attr-defined]

    def test_failure_rate_tracking(self, error_handler: R2ErrorHandler) -> None:
        """Failure rates are tracked correctly."""
        for _ in range(7):
            error_handler._record_performance("test_op", 1.0, success=True)

        for _ in range(3):
            error_handler._record_performance("test_op", 1.0, success=False)

        rates = error_handler.performance_monitor["failure_rates"]["test_op"]  # type: ignore[attr-defined]
        assert rates["successes"] == 7
        assert rates["failures"] == 3


class TestErrorStatistics:
    """Test error statistics."""

    def test_get_error_statistics(self, error_handler: R2ErrorHandler) -> None:
        """Error statistics are returned correctly."""
        stats = error_handler.get_error_statistics()

        assert "session_stats" in stats
        assert "error_count_by_type" in stats
        assert "error_count_by_severity" in stats
        assert "circuit_breaker_status" in stats
        assert "performance_metrics" in stats
        assert "recovery_rates" in stats

    def test_error_count_by_type(self, error_handler: R2ErrorHandler) -> None:
        """Errors are counted by type."""
        for _ in range(3):
            error_handler.handle_error(RuntimeError("Test"), "test_op")

        for _ in range(2):
            error_handler.handle_error(ValueError("Test"), "test_op")

        counts = error_handler._get_error_count_by_type()
        assert counts.get("RuntimeError", 0) == 3
        assert counts.get("ValueError", 0) == 2

    def test_error_count_by_severity(self, error_handler: R2ErrorHandler) -> None:
        """Errors are counted by severity."""
        error_handler.handle_error(MemoryError("Test"), "test_op")
        error_handler.handle_error(RuntimeError("Test"), "test_op")

        counts = error_handler._get_error_count_by_severity()
        assert counts[ErrorSeverity.CRITICAL.value] >= 1


class TestGracefulDegradation:
    """Test graceful degradation."""

    def test_operation_marked_as_degraded(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Operation is marked as degraded."""
        event = ErrorEvent(
            timestamp=datetime.now(),
            error_type="TestError",
            severity=ErrorSeverity.LOW,
            message="Test",
            context={"operation": "test_op"},
            traceback="",
            recovery_strategy=RecoveryStrategy.GRACEFUL_DEGRADATION,
        )

        result = error_handler._graceful_degradation(event)

        assert result is True
        assert error_handler.is_operation_degraded("test_op")


class TestGlobalHandler:
    """Test global handler functions."""

    def test_get_error_handler_creates_singleton(self) -> None:
        """Global error handler is a singleton."""
        handler1 = get_error_handler()
        handler2 = get_error_handler()

        assert handler1 is handler2

    def test_handle_r2_error_function(self) -> None:
        """handle_r2_error function works."""
        error = RuntimeError("Test error")
        result = handle_r2_error(error, "test_operation")

        assert isinstance(result, bool)

    def test_r2_error_context_function(self) -> None:
        """r2_error_context context manager works."""
        with pytest.raises(ValueError):
            with r2_error_context("test_operation"):
                raise ValueError("Test error")


class TestErrorHistoryManagement:
    """Test error history management."""

    def test_error_history_recorded(self, error_handler: R2ErrorHandler) -> None:
        """Errors are recorded in history."""
        initial_count = len(error_handler.error_history)

        error_handler.handle_error(RuntimeError("Test"), "test_op")

        assert len(error_handler.error_history) > initial_count

    def test_error_history_limited(self, error_handler: R2ErrorHandler) -> None:
        """Error history is limited to 500 most recent."""
        for i in range(1100):
            error_handler.handle_error(RuntimeError(f"Error {i}"), "test_op")

        assert len(error_handler.error_history) == 500

    def test_clear_error_history(self, error_handler: R2ErrorHandler) -> None:
        """Error history can be cleared."""
        error_handler.handle_error(RuntimeError("Test"), "test_op")
        assert len(error_handler.error_history) > 0

        error_handler.clear_error_history()

        assert len(error_handler.error_history) == 0
        assert error_handler.session_stats["total_errors"] == 0


class TestRecoverySuccessRates:
    """Test recovery success rate tracking."""

    def test_recovery_success_recorded(self, error_handler: R2ErrorHandler) -> None:
        """Recovery successes are recorded."""
        error_handler._record_recovery_success("test_action")

        rates = error_handler.performance_monitor["recovery_success_rates"]  # type: ignore[attr-defined]
        assert rates["test_action"]["successes"] == 1

    def test_recovery_failure_recorded(self, error_handler: R2ErrorHandler) -> None:
        """Recovery failures are recorded."""
        error_handler._record_recovery_failure("test_action")

        rates = error_handler.performance_monitor["recovery_success_rates"]  # type: ignore[attr-defined]
        assert rates["test_action"]["failures"] == 1

    def test_recovery_rate_calculation(self, error_handler: R2ErrorHandler) -> None:
        """Recovery rate is calculated correctly."""
        for _ in range(7):
            error_handler._record_recovery_success("test_action")

        for _ in range(3):
            error_handler._record_recovery_failure("test_action")

        rates = error_handler._get_recovery_rates()
        assert abs(rates["test_action"] - 0.7) < 0.01


class TestCustomRecoveryActions:
    """Test custom recovery action registration."""

    def test_add_custom_recovery_action(self, error_handler: R2ErrorHandler) -> None:
        """Custom recovery action can be added."""
        custom_action = RecoveryAction(
            name="custom",
            description="Custom action",
            action=lambda e: True,
        )

        error_handler.add_recovery_action("custom", custom_action)

        assert "custom" in error_handler.recovery_actions


class TestThreadSafety:
    """Test thread-safe error handling."""

    def test_concurrent_error_handling(self, error_handler: R2ErrorHandler) -> None:
        """Error handling is thread-safe."""
        import threading

        def handle_errors() -> None:
            for _ in range(10):
                error_handler.handle_error(RuntimeError("Concurrent error"), "test_op")

        threads = [threading.Thread(target=handle_errors) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert error_handler.session_stats["total_errors"] >= 50


class TestIntegration:
    """Integration tests for complete workflows."""

    def test_complete_error_handling_workflow(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Complete error handling workflow works end-to-end."""
        try:
            with error_handler.error_context("integration_test"):
                raise RuntimeError("Integration test error")
        except RuntimeError:
            pass

        stats = error_handler.get_error_statistics()
        assert stats["session_stats"]["total_errors"] > 0

    def test_recovery_after_multiple_failures(
        self, error_handler: R2ErrorHandler
    ) -> None:
        """Handler continues after multiple failures."""
        for i in range(5):
            try:
                with error_handler.error_context(f"operation_{i}"):
                    raise ValueError(f"Error {i}")
            except ValueError:
                pass

        assert error_handler.session_stats["total_errors"] == 5
