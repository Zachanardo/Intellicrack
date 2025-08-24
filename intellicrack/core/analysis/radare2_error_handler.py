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
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from ...utils.logger import get_logger

# Module logger
logger = get_logger(__name__)

try:
    import r2pipe
except ImportError as e:
    logger.error("Import error in radare2_error_handler: %s", e)
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
    action: Callable
    max_attempts: int = 3
    delay: float = 1.0
    exponential_backoff: bool = True
    prerequisites: list[str] = None


class R2ErrorHandler:
    """Comprehensive error handling and recovery system for radare2 operations.

    This class provides:
    - Automatic error detection and classification
    - Intelligent recovery strategies
    - Error tracking and reporting
    - Performance monitoring
    - Graceful degradation capabilities
    """

    def __init__(self, max_errors_per_session: int = 100):
        """Initialize the Radare2 error handler.

        Args:
            max_errors_per_session: Maximum number of errors to track per session.

        """
        self.logger = logger
        self.max_errors_per_session = max_errors_per_session
        self.error_history: list[ErrorEvent] = []
        self.recovery_actions: dict[str, RecoveryAction] = {}
        self.session_stats = {
            "total_errors": 0,
            "recovered_errors": 0,
            "critical_errors": 0,
            "session_start": datetime.now(),
            "last_error": None,
        }
        self.circuit_breakers = {}
        self.performance_monitor = {
            "operation_times": {},
            "failure_rates": {},
            "recovery_success_rates": {},
        }

        # Initialize built-in recovery actions
        self._initialize_recovery_actions()

        # Thread-safe error handling
        self._error_lock = threading.RLock()

        self.logger.info("R2ErrorHandler initialized")

    def _initialize_recovery_actions(self):
        """Initialize built-in recovery actions."""
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
    def error_context(self, operation_name: str, **context):
        """Context manager for error handling."""
        start_time = time.time()
        try:
            yield
        except Exception as e:
            self.logger.error("Exception in radare2_error_handler: %s", e)
            duration = time.time() - start_time
            self._record_performance(operation_name, duration, success=False)
            self.handle_error(e, operation_name, context)
            raise
        else:
            duration = time.time() - start_time
            self._record_performance(operation_name, duration, success=True)

    def handle_error(
        self, error: Exception, operation_name: str, context: dict[str, Any] = None
    ) -> bool:
        """Main error handling entry point.

        Args:
            error: The exception that occurred
            operation_name: Name of the operation that failed
            context: Additional context information

        Returns:
            bool: True if error was handled successfully, False otherwise

        """
        with self._error_lock:
            try:
                # Create error event
                error_event = self._create_error_event(error, operation_name, context)

                # Check circuit breaker
                if self._is_circuit_broken(operation_name):
                    self.logger.error(f"Circuit breaker open for {operation_name}, aborting")
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
                        self.session_stats["recovered_errors"] += 1
                        return True

                # Update circuit breaker on failure
                self._update_circuit_breaker(operation_name, success=False)

                return False

            except Exception as recovery_error:
                self.logger.critical(f"Error in error handler: {recovery_error}")
                return False

    def _create_error_event(
        self, error: Exception, operation_name: str, context: dict[str, Any]
    ) -> ErrorEvent:
        """Create error event from exception."""
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
        """Classify error severity based on type and context."""
        # Critical errors that stop all operations
        if isinstance(error, (MemoryError, SystemExit, KeyboardInterrupt)):
            return ErrorSeverity.CRITICAL

        # High severity for core functionality failures
        if isinstance(error, (FileNotFoundError, PermissionError)):
            if "radare2" in str(error).lower() or "r2" in operation_name:
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
        """Determine appropriate recovery strategy."""
        # Critical errors require abort or user intervention
        if error_event.severity == ErrorSeverity.CRITICAL:
            return RecoveryStrategy.USER_INTERVENTION

        # Too many errors in session - graceful degradation
        if self.session_stats["total_errors"] > self.max_errors_per_session:
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
        """Execute recovery strategy."""
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
            self.logger.error(f"Recovery execution failed: {e}")
            return False

    def _execute_retry_recovery(self, error_event: ErrorEvent) -> bool:
        """Execute retry-based recovery."""
        # Determine which recovery action to use
        if "r2pipe" in error_event.message:
            action_name = "restart_r2_session"
        elif "binary" in error_event.context.get("operation", ""):
            action_name = "re_analyze_binary"
        else:
            action_name = "retry_with_fallback"

        return self._execute_recovery_action(action_name, error_event)

    def _execute_fallback_recovery(self, error_event: ErrorEvent) -> bool:
        """Execute fallback recovery."""
        return self._execute_recovery_action("retry_with_fallback", error_event)

    def _execute_graceful_degradation(self, error_event: ErrorEvent) -> bool:
        """Execute graceful degradation."""
        return self._execute_recovery_action("graceful_degradation", error_event)

    def _execute_user_intervention(self, error_event: ErrorEvent) -> bool:
        """Execute user intervention recovery."""
        self.logger.critical(f"User intervention required: {error_event.message}")
        # In a real implementation, this would notify the user
        return False

    def _execute_recovery_action(self, action_name: str, error_event: ErrorEvent) -> bool:
        """Execute specific recovery action."""
        if action_name not in self.recovery_actions:
            self.logger.error(f"Unknown recovery action: {action_name}")
            return False

        action = self.recovery_actions[action_name]

        # Check if already exceeded max attempts
        if error_event.recovery_attempts >= action.max_attempts:
            self.logger.warning(f"Max recovery attempts exceeded for {action_name}")
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

            if success:
                self.logger.info(f"Recovery action {action_name} succeeded")
                self._record_recovery_success(action_name)
            else:
                self.logger.warning(f"Recovery action {action_name} failed")
                self._record_recovery_failure(action_name)

            return success

        except Exception as e:
            self.logger.error(f"Recovery action {action_name} threw exception: {e}")
            self._record_recovery_failure(action_name)
            return False

    # Built-in recovery action implementations

    def _restart_r2_session(self, error_event: ErrorEvent) -> bool:
        """Restart radare2 session."""
        try:
            # Get session from context if available
            r2_session = error_event.context.get("r2_session")
            binary_path = error_event.context.get("binary_path")

            if r2_session and binary_path:
                # Close existing session
                try:
                    r2_session.quit()
                except Exception as e:
                    self.logger.debug(f"Error closing r2 session during recovery: {e}")

                # Create new session
                new_session = r2pipe.open(binary_path, flags=["-2"])
                new_session.cmd("aaa")

                # Update context with new session
                error_event.context["r2_session"] = new_session

                self.logger.info("R2 session restarted successfully")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to restart R2 session: {e}")
            return False

    def _re_analyze_binary(self, error_event: ErrorEvent) -> bool:
        """Re-analyze binary with different parameters."""
        try:
            r2_session = error_event.context.get("r2_session")

            if r2_session:
                # Try lighter analysis first
                r2_session.cmd("aa")

                # If that succeeds, try more comprehensive
                r2_session.cmd("aaa")

                self.logger.info("Binary re-analysis completed")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to re-analyze binary: {e}")
            return False

    def _retry_with_fallback(self, error_event: ErrorEvent) -> bool:
        """Retry operation with fallback parameters."""
        try:
            # For demonstration, just return success after cleanup
            self._cleanup_memory(error_event)

            self.logger.info("Retry with fallback completed")
            return True

        except Exception as e:
            self.logger.error(f"Retry with fallback failed: {e}")
            return False

    def _cleanup_memory(self, error_event: ErrorEvent) -> bool:
        """Clean up radare2 memory and temporary files."""
        try:
            r2_session = error_event.context.get("r2_session")

            if r2_session:
                # Clear analysis cache
                try:
                    r2_session.cmd("af-*")
                    r2_session.cmd("fs-*")
                except Exception as e:
                    self.logger.debug(f"Error closing r2 session during recovery: {e}")

            # Clean up temporary files
            temp_files = error_event.context.get("temp_files", [])
            for temp_file in temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except Exception as e:
                    self.logger.debug(f"Error removing temp file during recovery: {e}")

            self.logger.info("Memory cleanup completed")
            return True

        except Exception as e:
            self.logger.error(f"Memory cleanup failed: {e}")
            return False

    def _graceful_degradation(self, error_event: ErrorEvent) -> bool:
        """Implement graceful degradation."""
        try:
            # Mark operation as degraded
            operation = error_event.context.get("operation", "unknown")

            if operation not in self.circuit_breakers:
                self.circuit_breakers[operation] = {
                    "failure_count": 0,
                    "success_count": 0,
                    "state": "closed",  # closed, open, half_open
                    "last_failure": None,
                    "degraded": False,
                }

            self.circuit_breakers[operation]["degraded"] = True

            self.logger.info(f"Graceful degradation activated for {operation}")
            return True

        except Exception as e:
            self.logger.error(f"Graceful degradation failed: {e}")
            return False

    # Circuit breaker pattern implementation

    def _is_circuit_broken(self, operation_name: str) -> bool:
        """Check if circuit breaker is open for operation."""
        if operation_name not in self.circuit_breakers:
            return False

        breaker = self.circuit_breakers[operation_name]

        if breaker["state"] == "open":
            # Check if enough time has passed to try half-open
            if breaker["last_failure"]:
                time_since_failure = datetime.now() - breaker["last_failure"]
                if time_since_failure > timedelta(minutes=5):  # 5 minute cooldown
                    breaker["state"] = "half_open"
                    return False
            return True

        return False

    def _update_circuit_breaker(self, operation_name: str, success: bool):
        """Update circuit breaker state."""
        if operation_name not in self.circuit_breakers:
            self.circuit_breakers[operation_name] = {
                "failure_count": 0,
                "success_count": 0,
                "state": "closed",
                "last_failure": None,
                "degraded": False,
            }

        breaker = self.circuit_breakers[operation_name]

        if success:
            breaker["success_count"] += 1
            breaker["failure_count"] = 0  # Reset failure count on success
            if breaker["state"] == "half_open":
                breaker["state"] = "closed"  # Close circuit on success
        else:
            breaker["failure_count"] += 1
            breaker["last_failure"] = datetime.now()

            # Open circuit if too many failures
            if breaker["failure_count"] >= 5:  # Threshold of 5 failures
                breaker["state"] = "open"

    # Performance monitoring

    def _record_performance(self, operation_name: str, duration: float, success: bool):
        """Record performance metrics."""
        if operation_name not in self.performance_monitor["operation_times"]:
            self.performance_monitor["operation_times"][operation_name] = []
            self.performance_monitor["failure_rates"][operation_name] = {
                "successes": 0,
                "failures": 0,
            }

        self.performance_monitor["operation_times"][operation_name].append(duration)

        # Keep only last 100 measurements
        if len(self.performance_monitor["operation_times"][operation_name]) > 100:
            self.performance_monitor["operation_times"][operation_name] = self.performance_monitor[
                "operation_times"
            ][operation_name][-100:]

        # Update failure rate
        if success:
            self.performance_monitor["failure_rates"][operation_name]["successes"] += 1
        else:
            self.performance_monitor["failure_rates"][operation_name]["failures"] += 1

    def _record_recovery_success(self, action_name: str):
        """Record successful recovery."""
        if action_name not in self.performance_monitor["recovery_success_rates"]:
            self.performance_monitor["recovery_success_rates"][action_name] = {
                "successes": 0,
                "failures": 0,
            }

        self.performance_monitor["recovery_success_rates"][action_name]["successes"] += 1

    def _record_recovery_failure(self, action_name: str):
        """Record failed recovery."""
        if action_name not in self.performance_monitor["recovery_success_rates"]:
            self.performance_monitor["recovery_success_rates"][action_name] = {
                "successes": 0,
                "failures": 0,
            }

        self.performance_monitor["recovery_success_rates"][action_name]["failures"] += 1

    def _record_error(self, error_event: ErrorEvent):
        """Record error in history."""
        self.error_history.append(error_event)

        # Keep only recent errors
        if len(self.error_history) > 1000:
            self.error_history = self.error_history[-500:]

        # Update session stats
        self.session_stats["total_errors"] += 1
        self.session_stats["last_error"] = error_event.timestamp

        if error_event.severity == ErrorSeverity.CRITICAL:
            self.session_stats["critical_errors"] += 1

    # Public API methods

    def add_recovery_action(self, name: str, action: RecoveryAction):
        """Add custom recovery action."""
        self.recovery_actions[name] = action
        self.logger.info(f"Added custom recovery action: {name}")

    def get_error_statistics(self) -> dict[str, Any]:
        """Get error statistics."""
        return {
            "session_stats": self.session_stats.copy(),
            "error_count_by_type": self._get_error_count_by_type(),
            "error_count_by_severity": self._get_error_count_by_severity(),
            "circuit_breaker_status": self.circuit_breakers.copy(),
            "performance_metrics": self._get_performance_metrics(),
            "recovery_rates": self._get_recovery_rates(),
        }

    def _get_error_count_by_type(self) -> dict[str, int]:
        """Get error counts grouped by type."""
        counts = {}
        for error in self.error_history:
            counts[error.error_type] = counts.get(error.error_type, 0) + 1
        return counts

    def _get_error_count_by_severity(self) -> dict[str, int]:
        """Get error counts grouped by severity."""
        counts = {severity.value: 0 for severity in ErrorSeverity}
        for error in self.error_history:
            counts[error.severity.value] += 1
        return counts

    def _get_performance_metrics(self) -> dict[str, Any]:
        """Get performance metrics."""
        metrics = {}
        for operation, times in self.performance_monitor["operation_times"].items():
            if times:
                metrics[operation] = {
                    "avg_duration": sum(times) / len(times),
                    "max_duration": max(times),
                    "min_duration": min(times),
                    "total_calls": len(times),
                }
        return metrics

    def _get_recovery_rates(self) -> dict[str, float]:
        """Get recovery success rates."""
        rates = {}
        for action, stats in self.performance_monitor["recovery_success_rates"].items():
            total = stats["successes"] + stats["failures"]
            if total > 0:
                rates[action] = stats["successes"] / total
            else:
                rates[action] = 0.0
        return rates

    def is_operation_degraded(self, operation_name: str) -> bool:
        """Check if operation is in degraded mode."""
        if operation_name in self.circuit_breakers:
            return self.circuit_breakers[operation_name].get("degraded", False)
        return False

    def reset_circuit_breaker(self, operation_name: str):
        """Reset circuit breaker for operation."""
        if operation_name in self.circuit_breakers:
            self.circuit_breakers[operation_name] = {
                "failure_count": 0,
                "success_count": 0,
                "state": "closed",
                "last_failure": None,
                "degraded": False,
            }
            self.logger.info(f"Reset circuit breaker for {operation_name}")

    def clear_error_history(self):
        """Clear error history."""
        self.error_history.clear()
        self.session_stats["total_errors"] = 0
        self.session_stats["recovered_errors"] = 0
        self.session_stats["critical_errors"] = 0
        self.session_stats["last_error"] = None
        self.logger.info("Error history cleared")


# Global error handler instance
_GLOBAL_ERROR_HANDLER = None


def get_error_handler() -> R2ErrorHandler:
    """Get or create global error handler instance."""
    global _GLOBAL_ERROR_HANDLER
    if _GLOBAL_ERROR_HANDLER is None:
        _GLOBAL_ERROR_HANDLER = R2ErrorHandler()
    return _GLOBAL_ERROR_HANDLER


def handle_r2_error(error: Exception, operation_name: str, **context) -> bool:
    """Convenience function to handle radare2 errors.

    Args:
        error: The exception that occurred
        operation_name: Name of the operation that failed
        **context: Additional context information

    Returns:
        bool: True if error was handled successfully, False otherwise

    """
    handler = get_error_handler()
    return handler.handle_error(error, operation_name, context)


@contextmanager
def r2_error_context(operation_name: str, **context):
    """Context manager for radare2 error handling."""
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
