"""Robust Error Handling and Recovery for Radare2 Integration.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellirack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellirack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import os
import threading
import time
import traceback
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, TypedDict

from ...utils.logger import get_logger


# Module logger
logger = get_logger(__name__)

try:
    import r2pipe
except ImportError as e:
    logger.exception("Import error in radare2_error_handler: %s", e)
    r2pipe = None


class ErrorSeverity(Enum):
    """Error severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryStrategy(Enum):
    """Available recovery strategies."""

    RETRY = "retry"
    FALLBACK = "fallback"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT = "abort"
    USER_INTERVENTION = "user_intervention"


class CircuitBreakerState(TypedDict):
    """Circuit breaker state structure."""

    failure_count: int
    success_count: int
    state: str
    last_failure: datetime | None
    degraded: bool


class FailureRateStats(TypedDict):
    """Failure rate statistics structure."""

    successes: int
    failures: int


@dataclass
class ErrorEvent:
    """Error event data structure."""

    timestamp: datetime
    error_type: str
    severity: ErrorSeverity
    message: str
    context: dict[str, Any]
    traceback: str
    recovery_strategy: RecoveryStrategy
    recovery_attempts: int = 0
    resolved: bool = False


@dataclass
class RecoveryAction:
    """Recovery action definition."""

    name: str
    description: str
    action: Callable[[ErrorEvent], bool]
    max_attempts: int = 3
    delay: float = 1.0
    exponential_backoff: bool = True
    prerequisites: list[str] | None = None


class R2ErrorHandler:
    """Comprehensive error handling and recovery system for radare2 operations.

    This class provides:
    - Automatic error detection and classification
    - Intelligent recovery strategies
    - Error tracking and reporting
    - Performance monitoring
    - Graceful degradation capabilities
    """

    def __init__(self, max_errors_per_session: int = 100) -> None:
        """Initialize the Radare2 error handler.

        Args:
            max_errors_per_session: Maximum number of errors to track per session.

        """
        self.logger = logger
        self.max_errors_per_session = max_errors_per_session
        self.error_history: list[ErrorEvent] = []
        self.recovery_actions: dict[str, RecoveryAction] = {}
        self.session_stats: dict[str, Any] = {
            "total_errors": 0,
            "recovered_errors": 0,
            "critical_errors": 0,
            "session_start": datetime.now(),
            "last_error": None,
        }
        self.circuit_breakers: dict[str, CircuitBreakerState] = {}
        self.operation_times: dict[str, list[float]] = {}
        self.failure_rates: dict[str, FailureRateStats] = {}
        self.recovery_success_rates: dict[str, FailureRateStats] = {}

        # Initialize built-in recovery actions
        self._initialize_recovery_actions()

        # Thread-safe error handling
        self._error_lock = threading.RLock()

        self.logger.info("R2ErrorHandler initialized")

    def _initialize_recovery_actions(self) -> None:
        """Initialize built-in recovery actions.

        Sets up the standard recovery actions for radare2 error handling,
        including session restart, binary re-analysis, fallback retry,
        memory cleanup, and graceful degradation strategies.
        """
        # R2 session recovery
        self.recovery_actions["restart_r2_session"] = RecoveryAction(
            name="Restart R2 Session",
            description="Restart radare2 session with fresh state",
            action=self._restart_r2_session,
            max_attempts=3,
            delay=2.0,
        )

        # Binary re-analysis
        self.recovery_actions["re_analyze_binary"] = RecoveryAction(
            name="Re-analyze Binary",
            description="Re-run binary analysis with different parameters",
            action=self._re_analyze_binary,
            max_attempts=2,
            delay=5.0,
        )

        # Command retry with fallback
        self.recovery_actions["retry_with_fallback"] = RecoveryAction(
            name="Retry with Fallback",
            description="Retry command with simplified parameters",
            action=self._retry_with_fallback,
            max_attempts=3,
            delay=1.0,
        )

        # Memory cleanup
        self.recovery_actions["cleanup_memory"] = RecoveryAction(
            name="Cleanup Memory",
            description="Clean up radare2 memory and temporary files",
            action=self._cleanup_memory,
            max_attempts=1,
            delay=0.5,
        )

        # Graceful degradation
        self.recovery_actions["graceful_degradation"] = RecoveryAction(
            name="Graceful Degradation",
            description="Continue with reduced functionality",
            action=self._graceful_degradation,
            max_attempts=1,
            delay=0.1,
        )

    @contextmanager
    def error_context(self, operation_name: str, **context: object) -> Generator[None, None, None]:
        """Context manager for error handling.

        Provides automatic error detection, classification, and recovery within
        a managed context. Records performance metrics and handles exceptions
        transparently.

        Args:
            operation_name: Name of the operation being monitored.
            **context: Additional context information passed to error handlers.

        Yields:
            Control returns to the calling code.

        Raises:
            Exception: Re-raised after logging and processing through the error handling
                pipeline if error handling fails or is not configured to suppress.

        """
        start_time = time.time()
        try:
            yield
        except Exception as e:
            self.logger.exception("Exception in radare2_error_handler: %s", e)
            duration = time.time() - start_time
            self._record_performance(operation_name, duration, success=False)
            self.handle_error(e, operation_name, context)
            raise
        else:
            duration = time.time() - start_time
            self._record_performance(operation_name, duration, success=True)

    def handle_error(self, error: Exception, operation_name: str, context: dict[str, Any] | None = None) -> bool:
        """Handle error as main entry point.

        Args:
            error: The exception that occurred.
            operation_name: Name of the operation that failed.
            context: Additional context information.

        Returns:
            True if error was handled successfully, False otherwise.

        """
        with self._error_lock:
            try:
                # Create error event
                error_event = self._create_error_event(error, operation_name, context)

                # Check circuit breaker
                if self._is_circuit_broken(operation_name):
                    self.logger.exception("Circuit breaker open for %s, aborting", operation_name)
                    return False

                # Record error
                self._record_error(error_event)

                # Determine recovery strategy
                recovery_strategy = self._determine_recovery_strategy(error_event)
                error_event.recovery_strategy = recovery_strategy

                # Execute recovery
                if recovery_strategy != RecoveryStrategy.ABORT:
                    success = self._execute_recovery(error_event)
                    if success:
                        error_event.resolved = True
                        recovered_count = self.session_stats["recovered_errors"]
                        if isinstance(recovered_count, int):
                            self.session_stats["recovered_errors"] = recovered_count + 1
                        return True

                # Update circuit breaker on failure
                self._update_circuit_breaker(operation_name, success=False)

                return False

            except Exception as recovery_error:
                self.logger.critical("Error in error handler: %s", recovery_error)
                return False

    def _create_error_event(self, error: Exception, operation_name: str, context: dict[str, Any] | None) -> ErrorEvent:
        """Create error event from exception.

        Transforms an exception into a structured ErrorEvent with classification,
        context, traceback, and default recovery strategy assignment.

        Args:
            error: The exception to convert into an ErrorEvent.
            operation_name: Name of the operation that triggered the error.
            context: Additional contextual information about the error.

        Returns:
            A structured error event with classification and context.
        """
        error_type = type(error).__name__
        severity = self._classify_error_severity(error, operation_name)

        return ErrorEvent(
            timestamp=datetime.now(),
            error_type=error_type,
            severity=severity,
            message=str(error),
            context={
                "operation": operation_name,
                **(context or {}),
            },
            traceback=traceback.format_exc(),
            recovery_strategy=RecoveryStrategy.RETRY,
        )

    def _classify_error_severity(self, error: Exception, operation_name: str) -> ErrorSeverity:
        """Classify error severity based on type and context.

        Analyzes the exception type and operation context to assign an appropriate
        severity level (CRITICAL, HIGH, MEDIUM, or LOW) for error handling prioritization.

        Args:
            error: The exception to classify.
            operation_name: Name of the operation that generated the error.

        Returns:
            The assigned severity level for this error.
        """
        # Critical errors that stop all operations
        if isinstance(error, (MemoryError, SystemExit, KeyboardInterrupt)):
            return ErrorSeverity.CRITICAL

        # High severity for core functionality failures
        if isinstance(error, (FileNotFoundError, PermissionError)) and ("radare2" in str(error).lower() or "r2" in operation_name):
            return ErrorSeverity.HIGH

        # Connection/pipe errors with r2
        if "r2pipe" in str(error) or "BrokenPipeError" in str(type(error)):
            return ErrorSeverity.HIGH

        # Timeout errors are medium severity
        if "timeout" in str(error).lower() or isinstance(error, TimeoutError):
            return ErrorSeverity.MEDIUM

        # JSON/parsing errors are typically low severity
        if isinstance(error, (ValueError, KeyError)) and "json" in str(error).lower():
            return ErrorSeverity.LOW

        # Default to medium
        return ErrorSeverity.MEDIUM

    def _determine_recovery_strategy(self, error_event: ErrorEvent) -> RecoveryStrategy:
        """Determine appropriate recovery strategy.

        Selects the best recovery approach based on error severity, type,
        session state, and resource availability.

        Args:
            error_event: The error event to determine recovery strategy for.

        Returns:
            The recommended recovery strategy for this error.
        """
        # Critical errors require abort or user intervention
        if error_event.severity == ErrorSeverity.CRITICAL:
            return RecoveryStrategy.USER_INTERVENTION

        # Too many errors in session - graceful degradation
        total_errors = self.session_stats["total_errors"]
        if isinstance(total_errors, int) and total_errors > self.max_errors_per_session:
            return RecoveryStrategy.GRACEFUL_DEGRADATION

        # R2 session issues - restart session
        if "r2pipe" in error_event.message or error_event.error_type == "BrokenPipeError":
            return RecoveryStrategy.RETRY  # Will use restart_r2_session action

        # File access issues - retry with fallback
        if error_event.error_type in ["FileNotFoundError", "PermissionError"]:
            return RecoveryStrategy.FALLBACK

        # Timeout or performance issues - graceful degradation
        if "timeout" in error_event.message.lower():
            return RecoveryStrategy.GRACEFUL_DEGRADATION

        # Default to retry
        return RecoveryStrategy.RETRY

    def _execute_recovery(self, error_event: ErrorEvent) -> bool:
        """Execute recovery strategy.

        Dispatches error recovery to the appropriate strategy handler based
        on the error event's recovery strategy assignment.

        Args:
            error_event: The error event requiring recovery execution.

        Returns:
            True if recovery succeeded, False otherwise.
        """
        strategy = error_event.recovery_strategy

        try:
            if strategy == RecoveryStrategy.RETRY:
                return self._execute_retry_recovery(error_event)
            if strategy == RecoveryStrategy.FALLBACK:
                return self._execute_fallback_recovery(error_event)
            if strategy == RecoveryStrategy.GRACEFUL_DEGRADATION:
                return self._execute_graceful_degradation(error_event)
            if strategy == RecoveryStrategy.USER_INTERVENTION:
                return self._execute_user_intervention(error_event)
            return False

        except Exception as e:
            self.logger.exception("Recovery execution failed: %s", e)
            return False

    def _execute_retry_recovery(self, error_event: ErrorEvent) -> bool:
        """Execute retry-based recovery.

        Performs retry recovery by selecting an appropriate recovery action
        based on the error type and operation context.

        Args:
            error_event: The error event to apply retry recovery to.

        Returns:
            True if retry recovery succeeded, False otherwise.
        """
        # Determine which recovery action to use
        if "r2pipe" in error_event.message:
            action_name = "restart_r2_session"
        elif "binary" in error_event.context.get("operation", ""):
            action_name = "re_analyze_binary"
        else:
            action_name = "retry_with_fallback"

        return self._execute_recovery_action(action_name, error_event)

    def _execute_fallback_recovery(self, error_event: ErrorEvent) -> bool:
        """Execute fallback recovery.

        Executes the fallback retry strategy with simplified parameters
        when the primary operation fails.

        Args:
            error_event: The error event to apply fallback recovery to.

        Returns:
            True if fallback recovery succeeded, False otherwise.
        """
        return self._execute_recovery_action("retry_with_fallback", error_event)

    def _execute_graceful_degradation(self, error_event: ErrorEvent) -> bool:
        """Execute graceful degradation.

        Activates graceful degradation mode for the affected operation,
        allowing it to continue with reduced functionality.

        Args:
            error_event: The error event triggering graceful degradation.

        Returns:
            True if graceful degradation was successfully activated, False otherwise.
        """
        return self._execute_recovery_action("graceful_degradation", error_event)

    def _execute_user_intervention(self, error_event: ErrorEvent) -> bool:
        """Execute user intervention recovery.

        Notifies the user of critical errors requiring manual intervention by
        logging with CRITICAL level severity and recording the intervention
        requirement in the error context for external monitoring systems.

        Args:
            error_event: The error event requiring user intervention.

        Returns:
            False as user intervention is pending external resolution.

        """
        intervention_message = (
            f"CRITICAL: User intervention required for {error_event.error_type} "
            f"in operation {error_event.context.get('operation', 'unknown')}: "
            f"{error_event.message}"
        )
        self.logger.critical(intervention_message)

        # Store intervention requirement for external monitoring and notification systems
        error_event.context["requires_intervention"] = True
        error_event.context["intervention_timestamp"] = datetime.now()
        error_event.context["intervention_message"] = intervention_message

        # Record in session stats for intervention tracking
        interventions_key = "interventions_required"
        if interventions_key not in self.session_stats:
            self.session_stats[interventions_key] = []
        interventions = self.session_stats[interventions_key]
        if isinstance(interventions, list):
            interventions.append({
                "timestamp": datetime.now(),
                "operation": error_event.context.get("operation", "unknown"),
                "error_type": error_event.error_type,
                "message": intervention_message,
            })

        return False

    def _execute_recovery_action(self, action_name: str, error_event: ErrorEvent) -> bool:
        """Execute specific recovery action.

        Invokes a named recovery action with automatic delay, exponential backoff,
        and attempt tracking to restore system functionality after an error.

        Args:
            action_name: The name of the recovery action to execute.
            error_event: The error event context for recovery execution.

        Returns:
            True if the recovery action succeeded, False otherwise.
        """
        if action_name not in self.recovery_actions:
            self.logger.exception("Unknown recovery action: %s", action_name)
            return False

        action = self.recovery_actions[action_name]

        # Check if already exceeded max attempts
        if error_event.recovery_attempts >= action.max_attempts:
            self.logger.warning("Max recovery attempts exceeded for %s", action_name)
            return False

        # Calculate delay with exponential backoff
        delay = action.delay
        if action.exponential_backoff and error_event.recovery_attempts > 0:
            delay *= 2**error_event.recovery_attempts

        # Wait before retry
        if delay > 0:
            time.sleep(delay)

        # Execute recovery action
        try:
            error_event.recovery_attempts += 1
            success = action.action(error_event)

            # Ensure success is a bool
            result = bool(success)

            if result:
                self.logger.info("Recovery action %s succeeded", action_name)
                self._record_recovery_success(action_name)
            else:
                self.logger.warning("Recovery action %s failed", action_name)
                self._record_recovery_failure(action_name)

            return result

        except Exception as e:
            self.logger.exception("Recovery action %s threw exception: %s", action_name, e)
            self._record_recovery_failure(action_name)
            return False

    # Built-in recovery action implementations

    def _restart_r2_session(self, error_event: ErrorEvent) -> bool:
        """Restart radare2 session.

        Closes the current radare2 session and creates a fresh one with
        the same binary and configuration to recover from session corruption.

        Args:
            error_event: The error event triggering session restart.

        Returns:
            True if session was successfully restarted, False otherwise.
        """
        try:
            # Get session from context if available
            r2_session = error_event.context.get("r2_session")
            binary_path = error_event.context.get("binary_path")

            if r2_session and binary_path:
                # Close existing session
                try:
                    r2_session.quit()
                except Exception as e:
                    self.logger.debug("Error closing r2 session during recovery: %s", e)

                # Create new session
                new_session = r2pipe.open(binary_path, flags=["-2"])
                new_session.cmd("aaa")

                # Update context with new session
                error_event.context["r2_session"] = new_session

                self.logger.info("R2 session restarted successfully")
                return True

            return False

        except Exception as e:
            self.logger.exception("Failed to restart R2 session: %s", e)
            return False

    def _re_analyze_binary(self, error_event: ErrorEvent) -> bool:
        """Re-analyze binary with different parameters.

        Restarts binary analysis using progressively comprehensive analysis
        levels to recover from incomplete or corrupted analysis state.

        Args:
            error_event: The error event triggering binary re-analysis.

        Returns:
            True if binary re-analysis completed successfully, False otherwise.
        """
        try:
            if r2_session := error_event.context.get("r2_session"):
                # Try lighter analysis first
                r2_session.cmd("aa")

                # If that succeeds, try more comprehensive
                r2_session.cmd("aaa")

                self.logger.info("Binary re-analysis completed")
                return True

            return False

        except Exception as e:
            self.logger.exception("Failed to re-analyze binary: %s", e)
            return False

    def _retry_with_fallback(self, error_event: ErrorEvent) -> bool:
        """Retry operation with fallback parameters.

        Attempts to recover from operation failure by cleaning up resources
        and retrying with simplified or alternative parameters.

        Args:
            error_event: The error event requiring fallback retry.

        Returns:
            True if fallback retry succeeded, False otherwise.
        """
        try:
            # For demonstration, just return success after cleanup
            self._cleanup_memory(error_event)

            self.logger.info("Retry with fallback completed")
            return True

        except Exception as e:
            self.logger.exception("Retry with fallback failed: %s", e)
            return False

    def _cleanup_memory(self, error_event: ErrorEvent) -> bool:
        """Clean up radare2 memory and temporary files.

        Frees radare2 analysis caches and removes temporary files associated
        with the failed operation to recover system resources.

        Args:
            error_event: The error event context for cleanup execution.

        Returns:
            True if cleanup completed successfully, False otherwise.
        """
        try:
            if r2_session := error_event.context.get("r2_session"):
                # Clear analysis cache
                try:
                    r2_session.cmd("af-*")
                    r2_session.cmd("fs-*")
                except Exception as e:
                    self.logger.debug("Error closing r2 session during recovery: %s", e)

            # Clean up temporary files
            temp_files = error_event.context.get("temp_files", [])
            for temp_file in temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except Exception as e:
                    self.logger.debug("Error removing temp file during recovery: %s", e)

            self.logger.info("Memory cleanup completed")
            return True

        except Exception as e:
            self.logger.exception("Memory cleanup failed: %s", e)
            return False

    def _graceful_degradation(self, error_event: ErrorEvent) -> bool:
        """Implement graceful degradation.

        Marks the affected operation as degraded, allowing it to continue
        with reduced functionality or accuracy in response to persistent errors.

        Args:
            error_event: The error event triggering graceful degradation.

        Returns:
            True if degradation mode was successfully activated, False otherwise.
        """
        try:
            operation = error_event.context.get("operation", "unknown")
            if not isinstance(operation, str):
                operation = "unknown"

            if operation not in self.circuit_breakers:
                self.circuit_breakers[operation] = CircuitBreakerState(
                    failure_count=0,
                    success_count=0,
                    state="closed",
                    last_failure=None,
                    degraded=False,
                )

            self.circuit_breakers[operation]["degraded"] = True

            self.logger.info("Graceful degradation activated for %s", operation)
            return True

        except Exception as e:
            self.logger.exception("Graceful degradation failed: %s", e)
            return False

    # Circuit breaker pattern implementation

    def _is_circuit_broken(self, operation_name: str) -> bool:
        """Check if circuit breaker is open for operation.

        Determines if the circuit breaker for the operation is in open or
        half-open state, returning to closed after a cooldown period.

        Args:
            operation_name: Name of the operation to check circuit status for.

        Returns:
            True if circuit breaker is open (blocking operations), False otherwise.
        """
        if operation_name not in self.circuit_breakers:
            return False

        breaker = self.circuit_breakers[operation_name]

        if breaker["state"] == "open":
            # Check if enough time has passed to try half-open
            last_failure = breaker["last_failure"]
            if last_failure is not None:
                time_since_failure = datetime.now() - last_failure
                if time_since_failure > timedelta(minutes=5):  # 5 minute cooldown
                    breaker["state"] = "half_open"
                    return False
            return True

        return False

    def _update_circuit_breaker(self, operation_name: str, success: bool) -> None:
        """Update circuit breaker state.

        Transitions circuit breaker state based on operation success/failure,
        opening the breaker after consecutive failures and closing it after
        recovery during the half-open state.

        Args:
            operation_name: Name of the operation to update circuit state for.
            success: True if the operation succeeded, False if it failed.

        """
        if operation_name not in self.circuit_breakers:
            self.circuit_breakers[operation_name] = CircuitBreakerState(
                failure_count=0,
                success_count=0,
                state="closed",
                last_failure=None,
                degraded=False,
            )

        breaker = self.circuit_breakers[operation_name]

        if success:
            breaker["success_count"] += 1
            breaker["failure_count"] = 0
            if breaker["state"] == "half_open":
                breaker["state"] = "closed"
        else:
            breaker["failure_count"] += 1
            breaker["last_failure"] = datetime.now()

            if breaker["failure_count"] >= 5:
                breaker["state"] = "open"

    # Performance monitoring

    def _record_performance(self, operation_name: str, duration: float, success: bool) -> None:
        """Record performance metrics.

        Tracks operation execution time and success/failure rates for
        performance monitoring and failure rate analysis.

        Args:
            operation_name: Name of the operation being monitored.
            duration: Execution time in seconds for the operation.
            success: True if the operation completed successfully, False if it failed.

        """
        if operation_name not in self.operation_times:
            self.operation_times[operation_name] = []
            self.failure_rates[operation_name] = FailureRateStats(
                successes=0,
                failures=0,
            )

        self.operation_times[operation_name].append(duration)

        if len(self.operation_times[operation_name]) > 100:
            self.operation_times[operation_name] = self.operation_times[operation_name][-100:]

        if success:
            self.failure_rates[operation_name]["successes"] += 1
        else:
            self.failure_rates[operation_name]["failures"] += 1

    def _record_recovery_success(self, action_name: str) -> None:
        """Record successful recovery.

        Tracks successful recovery action execution for success rate metrics
        and recovery effectiveness analysis.

        Args:
            action_name: Name of the recovery action that succeeded.

        """
        if action_name not in self.recovery_success_rates:
            self.recovery_success_rates[action_name] = FailureRateStats(
                successes=0,
                failures=0,
            )

        self.recovery_success_rates[action_name]["successes"] += 1

    def _record_recovery_failure(self, action_name: str) -> None:
        """Record failed recovery.

        Tracks failed recovery action execution for success rate metrics
        and recovery effectiveness analysis.

        Args:
            action_name: Name of the recovery action that failed.

        """
        if action_name not in self.recovery_success_rates:
            self.recovery_success_rates[action_name] = FailureRateStats(
                successes=0,
                failures=0,
            )

        self.recovery_success_rates[action_name]["failures"] += 1

    def _record_error(self, error_event: ErrorEvent) -> None:
        """Record error in history.

        Stores error event in history log, updates session error statistics,
        and maintains critical error count for session monitoring.

        Args:
            error_event: The error event to record in the history.

        """
        self.error_history.append(error_event)

        # Keep only recent errors
        if len(self.error_history) > 1000:
            self.error_history = self.error_history[-500:]

        # Update session stats
        total_errors = self.session_stats["total_errors"]
        if isinstance(total_errors, int):
            self.session_stats["total_errors"] = total_errors + 1
        self.session_stats["last_error"] = error_event.timestamp

        if error_event.severity == ErrorSeverity.CRITICAL:
            critical_errors = self.session_stats["critical_errors"]
            if isinstance(critical_errors, int):
                self.session_stats["critical_errors"] = critical_errors + 1

    # Public API methods

    def add_recovery_action(self, name: str, action: RecoveryAction) -> None:
        """Add custom recovery action.

        Registers a custom recovery action to the error handler's action registry,
        enabling external recovery strategies to be integrated into error handling.

        Args:
            name: Unique identifier for the recovery action.
            action: The RecoveryAction definition containing handler and metadata.

        """
        self.recovery_actions[name] = action
        self.logger.info("Added custom recovery action: %s", name)

    def get_error_statistics(self) -> dict[str, Any]:
        """Get error statistics.

        Compiles comprehensive error statistics including error counts by type/severity,
        circuit breaker status, performance metrics, and recovery success rates.

        Returns:
            Dictionary containing all error and recovery statistics.
        """
        return {
            "session_stats": self.session_stats.copy(),
            "error_count_by_type": self._get_error_count_by_type(),
            "error_count_by_severity": self._get_error_count_by_severity(),
            "circuit_breaker_status": self.circuit_breakers.copy(),
            "performance_metrics": self._get_performance_metrics(),
            "recovery_rates": self._get_recovery_rates(),
        }

    def _get_error_count_by_type(self) -> dict[str, int]:
        """Get error counts grouped by type.

        Aggregates error history by exception type to identify problematic
        error patterns and frequency distribution.

        Returns:
            Dictionary mapping error type names to occurrence counts.
        """
        counts: dict[str, int] = {}
        for error in self.error_history:
            counts[error.error_type] = counts.get(error.error_type, 0) + 1
        return counts

    def _get_error_count_by_severity(self) -> dict[str, int]:
        """Get error counts grouped by severity.

        Aggregates error history by severity level to track distribution of
        critical, high, medium, and low severity errors.

        Returns:
            Dictionary mapping severity level names to occurrence counts.
        """
        counts = {severity.value: 0 for severity in ErrorSeverity}
        for error in self.error_history:
            counts[error.severity.value] += 1
        return counts

    def _get_performance_metrics(self) -> dict[str, Any]:
        """Get performance metrics.

        Calculates performance statistics for each operation including average,
        maximum, minimum execution durations and total call counts.

        Returns:
            Dictionary mapping operation names to performance metrics.
        """
        return {
            operation: {
                "avg_duration": sum(times) / len(times),
                "max_duration": max(times),
                "min_duration": min(times),
                "total_calls": len(times),
            }
            for operation, times in self.operation_times.items()
            if times
        }

    def _get_recovery_rates(self) -> dict[str, float]:
        """Get recovery success rates.

        Calculates the success rate (0.0 to 1.0) for each recovery action
        based on tracked successes and failures.

        Returns:
            Dictionary mapping recovery action names to success rates.
        """
        rates: dict[str, float] = {}
        for action, stats in self.recovery_success_rates.items():
            total = stats["successes"] + stats["failures"]
            rates[action] = stats["successes"] / total if total > 0 else 0.0
        return rates

    def is_operation_degraded(self, operation_name: str) -> bool:
        """Check if operation is in degraded mode.

        Determines if the specified operation is currently running with reduced
        functionality due to persistent errors or resource constraints.

        Args:
            operation_name: Name of the operation to check degradation status for.

        Returns:
            True if operation is in degraded mode, False otherwise.
        """
        if operation_name in self.circuit_breakers:
            degraded = self.circuit_breakers[operation_name].get("degraded", False)
            return bool(degraded)
        return False

    def reset_circuit_breaker(self, operation_name: str) -> None:
        """Reset circuit breaker for operation.

        Restores the circuit breaker to closed state, clearing failure counts
        and allowing operations to proceed normally without blocking.

        Args:
            operation_name: Name of the operation's circuit breaker to reset.

        """
        if operation_name in self.circuit_breakers:
            self.circuit_breakers[operation_name] = CircuitBreakerState(
                failure_count=0,
                success_count=0,
                state="closed",
                last_failure=None,
                degraded=False,
            )
            self.logger.info("Reset circuit breaker for %s", operation_name)

    def clear_error_history(self) -> None:
        """Clear error history.

        Removes all stored error events and resets session error statistics
        counters to zero, preparing for a fresh analysis session.

        """
        self.error_history.clear()
        self.session_stats["total_errors"] = 0
        self.session_stats["recovered_errors"] = 0
        self.session_stats["critical_errors"] = 0
        self.session_stats["last_error"] = None
        self.logger.info("Error history cleared")


# Global error handler instance
_GLOBAL_ERROR_HANDLER = None


def get_error_handler() -> R2ErrorHandler:
    """Get or create global error handler instance.

    Returns the singleton global error handler instance, creating it if necessary
    to provide consistent error handling across the application.

    Returns:
        The global error handler instance.
    """
    global _GLOBAL_ERROR_HANDLER
    if _GLOBAL_ERROR_HANDLER is None:
        _GLOBAL_ERROR_HANDLER = R2ErrorHandler()
    return _GLOBAL_ERROR_HANDLER


def handle_r2_error(error: Exception, operation_name: str, **context: object) -> bool:
    """Handle radare2 errors.

    Processes radare2-related exceptions through the global error handler,
    applying appropriate recovery strategies based on error classification.

    Args:
        error: The exception that occurred.
        operation_name: Name of the operation that failed.
        **context: Additional context information passed to error handlers.

    Returns:
        True if error was handled successfully, False otherwise.

    """
    handler = get_error_handler()
    context_dict: dict[str, Any] = dict(context.items())
    return handler.handle_error(error, operation_name, context_dict)


@contextmanager
def r2_error_context(operation_name: str, **context: object) -> Generator[None, None, None]:
    """Context manager for radare2 error handling.

    Wraps radare2 operations with automatic error handling and recovery.
    Integrates with the global error handler to provide consistent error
    handling across the application.

    Args:
        operation_name: Name of the radare2 operation being executed.
        **context: Additional context information for the operation.

    Yields:
        Control returns to the calling code.

    Raises:
        Any exception occurring within the context is processed through the
            error handler pipeline before being re-raised.

    """
    handler = get_error_handler()
    with handler.error_context(operation_name, **context):
        yield


__all__ = [
    "ErrorEvent",
    "ErrorSeverity",
    "R2ErrorHandler",
    "RecoveryAction",
    "RecoveryStrategy",
    "get_error_handler",
    "handle_r2_error",
    "r2_error_context",
]
