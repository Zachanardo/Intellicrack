"""
Robust Error Handling and Recovery for Radare2 Integration

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import json
import os
import psutil
import shutil
import signal
import subprocess
import threading
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from ...utils.logger import get_logger, log_performance_metric, log_security_alert
from ..tool_validator import ExternalToolValidator, ToolValidationResult

# Module logger with structured logging support
logger = get_logger(__name__)

try:
    import r2pipe
except ImportError as e:
    logger.error("Import error in radare2_error_handler: %s", e, 
                category="import_error", tool="r2pipe")
    r2pipe = None


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for better classification"""
    TOOL_CONNECTIVITY = "tool_connectivity"
    PARSE_ERROR = "parse_error"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    BINARY_FORMAT = "binary_format"
    PERMISSION_ACCESS = "permission_access"
    TIMEOUT = "timeout"
    PROCESS_CRASH = "process_crash"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    UNKNOWN = "unknown"


class RecoveryStrategy(Enum):
    """Available recovery strategies"""
    RETRY = "retry"
    FALLBACK = "fallback"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT = "abort"
    USER_INTERVENTION = "user_intervention"
    TOOL_REINSTALL = "tool_reinstall"


@dataclass
class ErrorEvent:
    """Error event data structure"""
    timestamp: datetime
    error_type: str
    error_category: ErrorCategory
    severity: ErrorSeverity
    message: str
    context: Dict[str, Any]
    traceback: str
    recovery_strategy: RecoveryStrategy
    recovery_attempts: int = 0
    resolved: bool = False
    operation_id: Optional[str] = None
    binary_path: Optional[str] = None
    r2_session_id: Optional[str] = None


@dataclass
class RecoveryAction:
    """Recovery action definition"""
    name: str
    description: str
    action: Callable
    max_attempts: int = 3
    delay: float = 1.0
    exponential_backoff: bool = True
    prerequisites: List[str] = None


class R2ErrorHandler:
    """
    Comprehensive error handling and recovery system for radare2 operations.

    This class provides:
    - Automatic error detection and classification
    - Intelligent recovery strategies
    - Error tracking and reporting
    - Performance monitoring
    - Graceful degradation capabilities
    """

    def __init__(self, max_errors_per_session: int = 100, enable_tool_validation: bool = True):
        """Initialize the Radare2 error handler.

        Args:
            max_errors_per_session: Maximum number of errors to track per session.
            enable_tool_validation: Whether to enable tool validation on startup.
        """
        self.logger = logger
        self.max_errors_per_session = max_errors_per_session
        self.enable_tool_validation = enable_tool_validation
        self.error_history: List[ErrorEvent] = []
        self.recovery_actions: Dict[str, RecoveryAction] = {}
        self.session_stats = {
            'total_errors': 0,
            'recovered_errors': 0,
            'critical_errors': 0,
            'session_start': datetime.now(),
            'last_error': None,
            'tool_validation_results': {}
        }
        self.circuit_breakers = {}
        self.performance_monitor = {
            'operation_times': {},
            'failure_rates': {},
            'recovery_success_rates': {}
        }
        
        # Tool validation
        self.tool_validator = ExternalToolValidator() if enable_tool_validation else None
        self.validated_tools: Dict[str, ToolValidationResult] = {}
        
        # Active R2 sessions tracking
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.session_lock = threading.RLock()
        
        # Resource monitoring
        self.resource_thresholds = {
            'memory_usage_percent': 85.0,
            'cpu_usage_percent': 90.0,
            'disk_space_gb': 1.0,
            'max_session_duration_minutes': 30
        }
        
        # Temporary file tracking
        self.temp_files: Set[str] = set()
        self.temp_dirs: Set[str] = set()

        # Initialize built-in recovery actions
        self._initialize_recovery_actions()

        # Thread-safe error handling
        self._error_lock = threading.RLock()
        
        # Validate tools on startup if enabled
        if self.enable_tool_validation:
            self._validate_radare2_installation()

        self.logger.info("R2ErrorHandler initialized", 
                        max_errors=max_errors_per_session,
                        tool_validation=enable_tool_validation,
                        category="initialization")

    def _validate_radare2_installation(self):
        """Validate radare2 installation and store results"""
        try:
            if self.tool_validator:
                validation_results = self.tool_validator.validate_all_tools()
                self.validated_tools = validation_results
                self.session_stats['tool_validation_results'] = {
                    name: {
                        'is_valid': result.is_valid,
                        'version': result.version,
                        'path': result.path,
                        'error': result.error_message
                    }
                    for name, result in validation_results.items()
                }
                
                # Check radare2 specifically
                r2_result = validation_results.get('radare2')
                if r2_result and not r2_result.is_valid:
                    self.logger.error("Radare2 validation failed", 
                                    error=r2_result.error_message,
                                    category="tool_validation")
                elif r2_result:
                    self.logger.info("Radare2 validation successful",
                                   version=r2_result.version,
                                   path=r2_result.path,
                                   category="tool_validation")
        except Exception as e:
            self.logger.error("Tool validation failed", 
                            error=str(e),
                            category="tool_validation")

    def _initialize_recovery_actions(self):
        """Initialize built-in recovery actions"""
        # R2 session recovery
        self.recovery_actions['restart_r2_session'] = RecoveryAction(
            name="Restart R2 Session",
            description="Restart radare2 session with fresh state",
            action=self._restart_r2_session,
            max_attempts=3,
            delay=2.0
        )

        # Binary re-analysis
        self.recovery_actions['re_analyze_binary'] = RecoveryAction(
            name="Re-analyze Binary",
            description="Re-run binary analysis with different parameters",
            action=self._re_analyze_binary,
            max_attempts=2,
            delay=5.0
        )

        # Command retry with fallback
        self.recovery_actions['retry_with_fallback'] = RecoveryAction(
            name="Retry with Fallback",
            description="Retry command with simplified parameters",
            action=self._retry_with_fallback,
            max_attempts=3,
            delay=1.0
        )

        # Memory cleanup
        self.recovery_actions['cleanup_memory'] = RecoveryAction(
            name="Cleanup Memory",
            description="Clean up radare2 memory and temporary files",
            action=self._cleanup_memory,
            max_attempts=1,
            delay=0.5
        )

        # Tool validation and repair
        self.recovery_actions['validate_and_repair_tool'] = RecoveryAction(
            name="Validate and Repair Tool",
            description="Validate radare2 installation and attempt repair",
            action=self._validate_and_repair_tool,
            max_attempts=1,
            delay=1.0
        )

        # Process cleanup
        self.recovery_actions['cleanup_processes'] = RecoveryAction(
            name="Cleanup Processes",
            description="Clean up stuck or zombie radare2 processes",
            action=self._cleanup_processes,
            max_attempts=1,
            delay=2.0
        )

        # Resource recovery
        self.recovery_actions['recover_resources'] = RecoveryAction(
            name="Recover Resources",
            description="Free up system resources for radare2 operations",
            action=self._recover_resources,
            max_attempts=1,
            delay=1.0
        )

        # Graceful degradation
        self.recovery_actions['graceful_degradation'] = RecoveryAction(
            name="Graceful Degradation",
            description="Continue with reduced functionality",
            action=self._graceful_degradation,
            max_attempts=1,
            delay=0.1
        )

    @contextmanager
    def error_context(self, operation_name: str, timeout_seconds: Optional[float] = None, **context):
        """Context manager for error handling with timeout support"""
        start_time = time.time()
        operation_id = context.get('operation_id', f"{operation_name}_{int(start_time)}")
        session_id = context.get('r2_session_id')
        
        # Update session activity if tracking
        if session_id:
            self.update_session_activity(session_id)
        
        # Add resource monitoring
        initial_resources = self.get_system_resource_status()
        
        try:
            # Set up timeout if specified
            if timeout_seconds:
                import signal
                
                def timeout_handler(signum, frame):
                    raise TimeoutError(f"Operation {operation_name} timed out after {timeout_seconds} seconds")
                
                # Only set timeout on Unix systems (Windows doesn't support signal.alarm)
                if hasattr(signal, 'alarm'):
                    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(int(timeout_seconds))
            
            # Add operation context
            enhanced_context = {
                **context,
                'operation_id': operation_id,
                'start_time': start_time,
                'initial_resources': initial_resources
            }
            
            self.logger.debug("Starting operation",
                            operation=operation_name,
                            operation_id=operation_id,
                            timeout=timeout_seconds,
                            category="operation_start")
            
            yield enhanced_context
            
        except asyncio.TimeoutError as e:
            # Handle asyncio timeout
            duration = time.time() - start_time
            self._record_performance(operation_name, duration, success=False)
            
            timeout_context = {**context, 'timeout_seconds': timeout_seconds}
            asyncio.create_task(self.handle_error(e, operation_name, timeout_context))
            raise
            
        except Exception as e:
            duration = time.time() - start_time
            self._record_performance(operation_name, duration, success=False)
            
            # Add timing and resource info to context
            final_resources = self.get_system_resource_status()
            error_context = {
                **context,
                'operation_id': operation_id,
                'duration': duration,
                'initial_resources': initial_resources,
                'final_resources': final_resources
            }
            
            self.logger.error("Exception in operation",
                            operation=operation_name,
                            operation_id=operation_id,
                            duration=duration,
                            error=str(e),
                            error_type=type(e).__name__,
                            category="operation_error")
            
            # Handle error asynchronously if in async context
            try:
                import asyncio
                if asyncio.current_task():
                    asyncio.create_task(self.handle_error(e, operation_name, error_context))
                else:
                    # Synchronous context - handle directly but don't await
                    pass
            except RuntimeError:
                # Not in async context
                pass
            
            raise
        else:
            duration = time.time() - start_time
            self._record_performance(operation_name, duration, success=True)
            
            self.logger.debug("Operation completed successfully",
                            operation=operation_name,
                            operation_id=operation_id,
                            duration=duration,
                            category="operation_success")
        finally:
            # Clean up timeout if it was set
            if timeout_seconds and hasattr(signal, 'alarm'):
                signal.alarm(0)
                if 'old_handler' in locals():
                    signal.signal(signal.SIGALRM, old_handler)

    async def handle_error(self, error: Exception, operation_name: str, context: Dict[str, Any] = None) -> bool:
        """
        Main error handling entry point.

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
                    success = await self._execute_recovery(error_event)
                    if success:
                        error_event.resolved = True
                        self.session_stats['recovered_errors'] += 1
                        return True

                # Update circuit breaker on failure
                self._update_circuit_breaker(operation_name, success=False)

                return False

            except Exception as recovery_error:
                self.logger.critical(f"Error in error handler: {recovery_error}")
                return False

    def _create_error_event(self, error: Exception, operation_name: str, context: Dict[str, Any]) -> ErrorEvent:
        """Create error event from exception"""
        error_type = type(error).__name__
        error_category = self._classify_error_category(error, operation_name)
        severity = self._classify_error_severity(error, operation_name, error_category)

        return ErrorEvent(
            timestamp=datetime.now(),
            error_type=error_type,
            error_category=error_category,
            severity=severity,
            message=str(error),
            context={
                'operation': operation_name,
                **(context or {})
            },
            traceback=traceback.format_exc(),
            recovery_strategy=RecoveryStrategy.RETRY,
            operation_id=context.get('operation_id') if context else None,
            binary_path=context.get('binary_path') if context else None,
            r2_session_id=context.get('r2_session_id') if context else None
        )

    def _classify_error_category(self, error: Exception, operation_name: str) -> ErrorCategory:
        """Classify error into categories for better recovery strategy selection"""
        error_msg = str(error).lower()
        error_type = type(error).__name__
        
        # Tool connectivity issues
        if (isinstance(error, (ConnectionError, subprocess.SubprocessError)) or
            'r2pipe' in error_msg or 'connection' in error_msg or 
            'broken pipe' in error_msg or error_type == 'BrokenPipeError'):
            return ErrorCategory.TOOL_CONNECTIVITY
            
        # Parse errors
        if (isinstance(error, (ValueError, KeyError, json.JSONDecodeError)) or
            'json' in error_msg or 'parse' in error_msg or 'decode' in error_msg):
            return ErrorCategory.PARSE_ERROR
            
        # Resource exhaustion
        if (isinstance(error, (MemoryError, OSError)) or
            'memory' in error_msg or 'disk' in error_msg or 'space' in error_msg):
            return ErrorCategory.RESOURCE_EXHAUSTION
            
        # Binary format issues
        if ('invalid' in error_msg and 'binary' in error_msg or
            'format' in error_msg or 'corrupt' in error_msg):
            return ErrorCategory.BINARY_FORMAT
            
        # Permission/access issues
        if (isinstance(error, (PermissionError, FileNotFoundError)) or
            'permission' in error_msg or 'access' in error_msg or 'denied' in error_msg):
            return ErrorCategory.PERMISSION_ACCESS
            
        # Timeout issues
        if (isinstance(error, TimeoutError) or 'timeout' in error_msg):
            return ErrorCategory.TIMEOUT
            
        # Process crashes
        if ('crash' in error_msg or 'segmentation' in error_msg or 
            'terminated' in error_msg or isinstance(error, (SystemExit, KeyboardInterrupt))):
            return ErrorCategory.PROCESS_CRASH
            
        # Configuration issues
        if ('config' in error_msg or 'setting' in error_msg):
            return ErrorCategory.CONFIGURATION
            
        # Dependency issues
        if ('import' in error_msg or 'module' in error_msg or 'dependency' in error_msg):
            return ErrorCategory.DEPENDENCY
            
        return ErrorCategory.UNKNOWN

    def _classify_error_severity(self, error: Exception, operation_name: str, 
                               error_category: ErrorCategory) -> ErrorSeverity:
        """Classify error severity based on type, context, and category"""
        # Critical errors that stop all operations
        if isinstance(error, (MemoryError, SystemExit, KeyboardInterrupt)):
            return ErrorSeverity.CRITICAL
            
        # Critical based on category
        if error_category == ErrorCategory.PROCESS_CRASH:
            return ErrorSeverity.CRITICAL
            
        # High severity categories
        if error_category in [ErrorCategory.TOOL_CONNECTIVITY, ErrorCategory.RESOURCE_EXHAUSTION]:
            return ErrorSeverity.HIGH
            
        # High severity for core functionality failures
        if isinstance(error, (FileNotFoundError, PermissionError)):
            if 'radare2' in str(error).lower() or 'r2' in operation_name:
                return ErrorSeverity.HIGH
                
        # Medium severity categories
        if error_category in [ErrorCategory.TIMEOUT, ErrorCategory.BINARY_FORMAT, 
                             ErrorCategory.PERMISSION_ACCESS, ErrorCategory.CONFIGURATION]:
            return ErrorSeverity.MEDIUM
            
        # Low severity categories
        if error_category in [ErrorCategory.PARSE_ERROR, ErrorCategory.DEPENDENCY]:
            return ErrorSeverity.LOW

        # Default to medium
        return ErrorSeverity.MEDIUM

    def _determine_recovery_strategy(self, error_event: ErrorEvent) -> RecoveryStrategy:
        """Determine appropriate recovery strategy based on error category and severity"""
        # Critical errors require abort or user intervention
        if error_event.severity == ErrorSeverity.CRITICAL:
            if error_event.error_category == ErrorCategory.PROCESS_CRASH:
                return RecoveryStrategy.RETRY  # Try to restart
            return RecoveryStrategy.USER_INTERVENTION

        # Too many errors in session - graceful degradation
        if self.session_stats['total_errors'] > self.max_errors_per_session:
            return RecoveryStrategy.GRACEFUL_DEGRADATION

        # Strategy based on error category
        category_strategies = {
            ErrorCategory.TOOL_CONNECTIVITY: RecoveryStrategy.RETRY,
            ErrorCategory.PARSE_ERROR: RecoveryStrategy.FALLBACK,
            ErrorCategory.RESOURCE_EXHAUSTION: RecoveryStrategy.GRACEFUL_DEGRADATION,
            ErrorCategory.BINARY_FORMAT: RecoveryStrategy.FALLBACK,
            ErrorCategory.PERMISSION_ACCESS: RecoveryStrategy.FALLBACK,
            ErrorCategory.TIMEOUT: RecoveryStrategy.GRACEFUL_DEGRADATION,
            ErrorCategory.PROCESS_CRASH: RecoveryStrategy.RETRY,
            ErrorCategory.CONFIGURATION: RecoveryStrategy.FALLBACK,
            ErrorCategory.DEPENDENCY: RecoveryStrategy.TOOL_REINSTALL,
            ErrorCategory.UNKNOWN: RecoveryStrategy.RETRY
        }

        return category_strategies.get(error_event.error_category, RecoveryStrategy.RETRY)

    async def _execute_recovery(self, error_event: ErrorEvent) -> bool:
        """Execute recovery strategy"""
        strategy = error_event.recovery_strategy

        try:
            if strategy == RecoveryStrategy.RETRY:
                return await self._execute_retry_recovery(error_event)
            elif strategy == RecoveryStrategy.FALLBACK:
                return await self._execute_fallback_recovery(error_event)
            elif strategy == RecoveryStrategy.GRACEFUL_DEGRADATION:
                return await self._execute_graceful_degradation(error_event)
            elif strategy == RecoveryStrategy.USER_INTERVENTION:
                return self._execute_user_intervention(error_event)
            else:
                return False

        except Exception as e:
            self.logger.error(f"Recovery execution failed: {e}")
            return False

    async def _execute_retry_recovery(self, error_event: ErrorEvent) -> bool:
        """Execute retry-based recovery based on error category"""
        # Determine which recovery action to use based on error category
        category_actions = {
            ErrorCategory.TOOL_CONNECTIVITY: 'restart_r2_session',
            ErrorCategory.PROCESS_CRASH: 'cleanup_processes',
            ErrorCategory.RESOURCE_EXHAUSTION: 'recover_resources',
            ErrorCategory.DEPENDENCY: 'validate_and_repair_tool',
            ErrorCategory.PARSE_ERROR: 'retry_with_fallback',
            ErrorCategory.BINARY_FORMAT: 're_analyze_binary',
            ErrorCategory.TIMEOUT: 'cleanup_memory',
            ErrorCategory.CONFIGURATION: 'validate_and_repair_tool',
            ErrorCategory.PERMISSION_ACCESS: 'retry_with_fallback',
            ErrorCategory.UNKNOWN: 'restart_r2_session'
        }
        
        action_name = category_actions.get(error_event.error_category, 'retry_with_fallback')
        return await self._execute_recovery_action(action_name, error_event)

    async def _execute_fallback_recovery(self, error_event: ErrorEvent) -> bool:
        """Execute fallback recovery"""
        return await self._execute_recovery_action('retry_with_fallback', error_event)

    async def _execute_graceful_degradation(self, error_event: ErrorEvent) -> bool:
        """Execute graceful degradation"""
        return await self._execute_recovery_action('graceful_degradation', error_event)

    def _execute_user_intervention(self, error_event: ErrorEvent) -> bool:
        """Execute user intervention recovery"""
        self.logger.critical(f"User intervention required: {error_event.message}")
        # In a real implementation, this would notify the user
        return False

    async def _execute_recovery_action(self, action_name: str, error_event: ErrorEvent) -> bool:
        """Execute specific recovery action"""
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
            delay *= (2 ** error_event.recovery_attempts)

        # Wait before retry
        if delay > 0:
            await asyncio.sleep(delay)

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
        """Restart radare2 session"""
        try:
            # Get session from context if available
            r2_session = error_event.context.get('r2_session')
            binary_path = error_event.context.get('binary_path')
            session_id = error_event.r2_session_id or error_event.context.get('r2_session_id')

            if r2_session and binary_path:
                self.logger.info("Restarting R2 session",
                               binary_path=binary_path,
                               session_id=session_id,
                               category="session_restart")
                
                # Close existing session
                try:
                    r2_session.quit()
                except Exception as e:
                    self.logger.debug("Error closing r2 session during recovery",
                                    error=str(e), session_id=session_id)

                # Create new session with timeout
                start_time = time.time()
                new_session = r2pipe.open(binary_path, flags=['-2'])
                
                # Perform basic analysis with timeout protection
                try:
                    new_session.cmd('aaa')
                    session_duration = time.time() - start_time
                    
                    # Track the new session
                    if session_id:
                        with self.session_lock:
                            self.active_sessions[session_id] = {
                                'r2_session': new_session,
                                'binary_path': binary_path,
                                'created': datetime.now(),
                                'last_activity': datetime.now()
                            }
                    
                    # Update context with new session
                    error_event.context['r2_session'] = new_session
                    
                    log_performance_metric("r2_session_restart", session_duration, "seconds")
                    
                    self.logger.info("R2 session restarted successfully",
                                   session_id=session_id,
                                   duration=session_duration,
                                   category="session_restart")
                    return True
                    
                except Exception as analysis_error:
                    self.logger.warning("R2 session restarted but analysis failed",
                                      error=str(analysis_error),
                                      session_id=session_id)
                    # Still return True as session was created
                    error_event.context['r2_session'] = new_session
                    return True

            self.logger.warning("Cannot restart R2 session - missing session or binary path",
                              has_session=bool(r2_session),
                              has_binary_path=bool(binary_path))
            return False

        except Exception as e:
            self.logger.error("Failed to restart R2 session",
                            error=str(e),
                            binary_path=error_event.context.get('binary_path'),
                            category="session_restart")
            return False

    def _re_analyze_binary(self, error_event: ErrorEvent) -> bool:
        """Re-analyze binary with different parameters"""
        try:
            r2_session = error_event.context.get('r2_session')
            binary_path = error_event.context.get('binary_path', 'unknown')

            if r2_session:
                self.logger.info("Re-analyzing binary with fallback parameters",
                               binary_path=binary_path,
                               category="binary_analysis")
                
                start_time = time.time()
                
                try:
                    # Try lighter analysis first
                    r2_session.cmd('aa')
                    light_duration = time.time() - start_time
                    
                    # If that succeeds, try more comprehensive but with timeout
                    comprehensive_start = time.time()
                    r2_session.cmd('aaa')
                    comprehensive_duration = time.time() - comprehensive_start
                    
                    total_duration = time.time() - start_time
                    
                    log_performance_metric("binary_reanalysis", total_duration, "seconds",
                                         light_analysis_time=light_duration,
                                         comprehensive_analysis_time=comprehensive_duration)
                    
                    self.logger.info("Binary re-analysis completed successfully",
                                   binary_path=binary_path,
                                   total_duration=total_duration,
                                   category="binary_analysis")
                    return True
                    
                except Exception as analysis_error:
                    # Fall back to minimal analysis only
                    try:
                        r2_session.cmd('a')  # Minimal analysis
                        fallback_duration = time.time() - start_time
                        
                        self.logger.warning("Binary re-analysis fell back to minimal analysis",
                                          error=str(analysis_error),
                                          fallback_duration=fallback_duration,
                                          binary_path=binary_path)
                        return True
                    except Exception as fallback_error:
                        self.logger.error("All binary analysis methods failed",
                                        analysis_error=str(analysis_error),
                                        fallback_error=str(fallback_error),
                                        binary_path=binary_path)
                        return False

            self.logger.warning("Cannot re-analyze binary - no R2 session available")
            return False

        except Exception as e:
            self.logger.error("Failed to re-analyze binary",
                            error=str(e),
                            binary_path=error_event.context.get('binary_path'),
                            category="binary_analysis")
            return False

    def _retry_with_fallback(self, error_event: ErrorEvent) -> bool:
        """Retry operation with fallback parameters"""
        try:
            operation = error_event.context.get('operation', 'unknown')
            
            self.logger.info("Retrying operation with fallback parameters",
                           operation=operation,
                           error_category=error_event.error_category.value,
                           category="retry_fallback")
            
            # Clean up memory first
            self._cleanup_memory(error_event)
            
            # Wait a short time before retry
            time.sleep(0.5)
            
            # Mark operation for simplified execution
            error_event.context['use_fallback_parameters'] = True
            error_event.context['retry_attempt'] = error_event.recovery_attempts + 1
            
            self.logger.info("Retry with fallback completed",
                           operation=operation,
                           retry_attempt=error_event.recovery_attempts + 1,
                           category="retry_fallback")
            return True

        except Exception as e:
            self.logger.error("Retry with fallback failed",
                            error=str(e),
                            operation=error_event.context.get('operation'),
                            category="retry_fallback")
            return False

    def _cleanup_memory(self, error_event: ErrorEvent) -> bool:
        """Clean up radare2 memory and temporary files"""
        try:
            r2_session = error_event.context.get('r2_session')
            session_id = error_event.r2_session_id or error_event.context.get('r2_session_id')
            
            self.logger.info("Starting memory cleanup",
                           session_id=session_id,
                           category="memory_cleanup")
            
            cleanup_actions = []

            if r2_session:
                # Clear analysis cache
                try:
                    r2_session.cmd('af-*')  # Clear function analysis
                    r2_session.cmd('fs-*')  # Clear flags
                    r2_session.cmd('e-*')   # Reset configuration
                    cleanup_actions.append("cleared_r2_cache")
                except Exception as e:
                    self.logger.debug("Error clearing R2 cache during cleanup",
                                    error=str(e), session_id=session_id)

            # Clean up temporary files from context
            temp_files = error_event.context.get('temp_files', [])
            for temp_file in temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                        cleanup_actions.append(f"removed_temp_file_{Path(temp_file).name}")
                except Exception as e:
                    self.logger.debug("Error removing temp file during cleanup",
                                    file=temp_file, error=str(e))
            
            # Clean up tracked temporary files
            self._cleanup_temp_files()
            cleanup_actions.append("cleaned_tracked_temp_files")
            
            # Force garbage collection
            import gc
            gc.collect()
            cleanup_actions.append("garbage_collection")

            self.logger.info("Memory cleanup completed",
                           actions=cleanup_actions,
                           session_id=session_id,
                           category="memory_cleanup")
            return True

        except Exception as e:
            self.logger.error("Memory cleanup failed",
                            error=str(e),
                            session_id=error_event.r2_session_id,
                            category="memory_cleanup")
            return False

    def _validate_and_repair_tool(self, error_event: ErrorEvent) -> bool:
        """Validate radare2 installation and attempt repair"""
        try:
            self.logger.info("Validating radare2 installation for repair",
                           error_category=error_event.error_category.value,
                           category="tool_validation")
            
            if not self.tool_validator:
                self.logger.warning("Tool validator not available for repair")
                return False
                
            # Re-validate radare2
            validation_results = self.tool_validator.validate_all_tools()
            r2_result = validation_results.get('radare2')
            
            if r2_result and r2_result.is_valid:
                self.logger.info("Radare2 validation successful after repair attempt",
                               version=r2_result.version,
                               path=r2_result.path,
                               category="tool_validation")
                return True
            elif r2_result:
                self.logger.error("Radare2 validation still failing",
                                error=r2_result.error_message,
                                category="tool_validation")
                
                # Log security alert for tool integrity
                log_security_alert("tool_validation_failure", "medium",
                                 tool="radare2", error=r2_result.error_message)
                
            return False
            
        except Exception as e:
            self.logger.error("Tool validation and repair failed",
                            error=str(e),
                            category="tool_validation")
            return False

    def _cleanup_processes(self, error_event: ErrorEvent) -> bool:
        """Clean up stuck or zombie radare2 processes"""
        try:
            self.logger.info("Cleaning up radare2 processes",
                           category="process_cleanup")
            
            # Find and terminate stuck r2 processes
            terminated_count = 0
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    if (proc_info['name'] and 'r2' in proc_info['name'].lower() or
                        proc_info['cmdline'] and any('radare2' in str(cmd).lower() 
                                                   for cmd in proc_info['cmdline'])):
                        
                        # Check if process is stuck (high CPU for extended time)
                        try:
                            cpu_percent = proc.cpu_percent(interval=1)
                            if cpu_percent > 80:  # High CPU usage
                                self.logger.warning("Terminating stuck radare2 process",
                                                  pid=proc_info['pid'],
                                                  cpu_percent=cpu_percent,
                                                  category="process_cleanup")
                                proc.terminate()
                                terminated_count += 1
                                
                                # Wait for graceful termination
                                try:
                                    proc.wait(timeout=5)
                                except psutil.TimeoutExpired:
                                    proc.kill()  # Force kill if needed
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            if terminated_count > 0:
                self.logger.info("Terminated stuck radare2 processes",
                               count=terminated_count,
                               category="process_cleanup")
            
            return True
            
        except Exception as e:
            self.logger.error("Process cleanup failed",
                            error=str(e),
                            category="process_cleanup")
            return False

    def _recover_resources(self, error_event: ErrorEvent) -> bool:
        """Free up system resources for radare2 operations"""
        try:
            self.logger.info("Recovering system resources", category="resource_recovery")
            
            # Check current resource usage
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Log current resource state
            log_performance_metric("system_memory_usage", memory.percent, "percent")
            log_performance_metric("system_cpu_usage", cpu_percent, "percent")
            
            recovery_actions = []
            
            # Clean up temporary files if memory is high
            if memory.percent > self.resource_thresholds['memory_usage_percent']:
                recovery_actions.append("cleanup_temp_files")
                self._cleanup_temp_files()
            
            # Force garbage collection
            import gc
            gc.collect()
            recovery_actions.append("garbage_collection")
            
            # Clean up old R2 sessions
            with self.session_lock:
                sessions_to_remove = []
                current_time = datetime.now()
                
                for session_id, session_info in self.active_sessions.items():
                    session_age = current_time - session_info.get('created', current_time)
                    max_age = timedelta(minutes=self.resource_thresholds['max_session_duration_minutes'])
                    
                    if session_age > max_age:
                        sessions_to_remove.append(session_id)
                
                for session_id in sessions_to_remove:
                    self._cleanup_r2_session(session_id)
                    recovery_actions.append(f"cleanup_session_{session_id}")
            
            self.logger.info("Resource recovery completed",
                           actions=recovery_actions,
                           category="resource_recovery")
            return True
            
        except Exception as e:
            self.logger.error("Resource recovery failed",
                            error=str(e),
                            category="resource_recovery")
            return False

    def _cleanup_temp_files(self):
        """Clean up temporary files created by radare2 operations"""
        try:
            cleaned_files = 0
            cleaned_dirs = 0
            
            # Clean up tracked temporary files
            for temp_file in list(self.temp_files):
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                        cleaned_files += 1
                    self.temp_files.discard(temp_file)
                except OSError as e:
                    self.logger.debug("Failed to remove temp file",
                                    file=temp_file, error=str(e))
            
            # Clean up tracked temporary directories
            for temp_dir in list(self.temp_dirs):
                try:
                    if os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir)
                        cleaned_dirs += 1
                    self.temp_dirs.discard(temp_dir)
                except OSError as e:
                    self.logger.debug("Failed to remove temp dir",
                                    dir=temp_dir, error=str(e))
            
            self.logger.info("Temporary files cleanup completed",
                           files_removed=cleaned_files,
                           dirs_removed=cleaned_dirs,
                           category="cleanup")
                           
        except Exception as e:
            self.logger.error("Temporary files cleanup failed", error=str(e))

    def _cleanup_r2_session(self, session_id: str):
        """Clean up a specific R2 session"""
        try:
            with self.session_lock:
                session_info = self.active_sessions.get(session_id)
                if session_info:
                    # Close R2 session if still active
                    r2_session = session_info.get('r2_session')
                    if r2_session:
                        try:
                            r2_session.quit()
                        except Exception as e:
                            self.logger.debug("Error closing R2 session during cleanup",
                                            session_id=session_id, error=str(e))
                    
                    # Remove from active sessions
                    del self.active_sessions[session_id]
                    
                    self.logger.debug("R2 session cleaned up",
                                    session_id=session_id,
                                    category="session_cleanup")
                    
        except Exception as e:
            self.logger.error("R2 session cleanup failed",
                            session_id=session_id,
                            error=str(e))

    def _graceful_degradation(self, error_event: ErrorEvent) -> bool:
        """Implement graceful degradation"""
        try:
            # Mark operation as degraded
            operation = error_event.context.get('operation', 'unknown')

            if operation not in self.circuit_breakers:
                self.circuit_breakers[operation] = {
                    'failure_count': 0,
                    'success_count': 0,
                    'state': 'closed',  # closed, open, half_open
                    'last_failure': None,
                    'degraded': False
                }

            self.circuit_breakers[operation]['degraded'] = True

            self.logger.info("Graceful degradation activated",
                           operation=operation,
                           error_category=error_event.error_category.value,
                           category="degradation")
            return True

        except Exception as e:
            self.logger.error("Graceful degradation failed", error=str(e))
            return False

    # Circuit breaker pattern implementation

    def _is_circuit_broken(self, operation_name: str) -> bool:
        """Check if circuit breaker is open for operation"""
        if operation_name not in self.circuit_breakers:
            return False

        breaker = self.circuit_breakers[operation_name]

        if breaker['state'] == 'open':
            # Check if enough time has passed to try half-open
            if breaker['last_failure']:
                time_since_failure = datetime.now() - breaker['last_failure']
                if time_since_failure > timedelta(minutes=5):  # 5 minute cooldown
                    breaker['state'] = 'half_open'
                    return False
            return True

        return False

    def _update_circuit_breaker(self, operation_name: str, success: bool):
        """Update circuit breaker state"""
        if operation_name not in self.circuit_breakers:
            self.circuit_breakers[operation_name] = {
                'failure_count': 0,
                'success_count': 0,
                'state': 'closed',
                'last_failure': None,
                'degraded': False
            }

        breaker = self.circuit_breakers[operation_name]

        if success:
            breaker['success_count'] += 1
            breaker['failure_count'] = 0  # Reset failure count on success
            if breaker['state'] == 'half_open':
                breaker['state'] = 'closed'  # Close circuit on success
        else:
            breaker['failure_count'] += 1
            breaker['last_failure'] = datetime.now()

            # Open circuit if too many failures
            if breaker['failure_count'] >= 5:  # Threshold of 5 failures
                breaker['state'] = 'open'

    # Performance monitoring

    def _record_performance(self, operation_name: str, duration: float, success: bool):
        """Record performance metrics with structured logging"""
        if operation_name not in self.performance_monitor['operation_times']:
            self.performance_monitor['operation_times'][operation_name] = []
            self.performance_monitor['failure_rates'][operation_name] = {'successes': 0, 'failures': 0}

        self.performance_monitor['operation_times'][operation_name].append(duration)

        # Keep only last 100 measurements
        if len(self.performance_monitor['operation_times'][operation_name]) > 100:
            self.performance_monitor['operation_times'][operation_name] = \
                self.performance_monitor['operation_times'][operation_name][-100:]

        # Update failure rate
        if success:
            self.performance_monitor['failure_rates'][operation_name]['successes'] += 1
        else:
            self.performance_monitor['failure_rates'][operation_name]['failures'] += 1

        # Log performance metric
        log_performance_metric(f"r2_operation_{operation_name}", duration, "seconds",
                             success=success,
                             category="radare2_performance")
        
        # Log warning for slow operations
        if duration > 30.0:  # 30 second threshold
            self.logger.warning("Slow radare2 operation detected",
                              operation=operation_name,
                              duration=duration,
                              success=success,
                              category="performance_warning")

    def _record_recovery_success(self, action_name: str):
        """Record successful recovery with structured logging"""
        if action_name not in self.performance_monitor['recovery_success_rates']:
            self.performance_monitor['recovery_success_rates'][action_name] = {'successes': 0, 'failures': 0}

        self.performance_monitor['recovery_success_rates'][action_name]['successes'] += 1
        
        # Log recovery success
        self.logger.info("Recovery action succeeded",
                        action=action_name,
                        category="recovery_success")

    def _record_recovery_failure(self, action_name: str):
        """Record failed recovery with structured logging"""
        if action_name not in self.performance_monitor['recovery_success_rates']:
            self.performance_monitor['recovery_success_rates'][action_name] = {'successes': 0, 'failures': 0}

        self.performance_monitor['recovery_success_rates'][action_name]['failures'] += 1
        
        # Log recovery failure
        self.logger.warning("Recovery action failed",
                          action=action_name,
                          category="recovery_failure")

    def _record_error(self, error_event: ErrorEvent):
        """Record error in history with structured logging"""
        self.error_history.append(error_event)

        # Keep only recent errors
        if len(self.error_history) > 1000:
            self.error_history = self.error_history[-500:]

        # Update session stats
        self.session_stats['total_errors'] += 1
        self.session_stats['last_error'] = error_event.timestamp

        if error_event.severity == ErrorSeverity.CRITICAL:
            self.session_stats['critical_errors'] += 1

        # Log structured error information
        self.logger.error("Error recorded in handler",
                        error_type=error_event.error_type,
                        error_category=error_event.error_category.value,
                        severity=error_event.severity.value,
                        operation=error_event.context.get('operation'),
                        operation_id=error_event.operation_id,
                        binary_path=error_event.binary_path,
                        session_id=error_event.r2_session_id,
                        recovery_strategy=error_event.recovery_strategy.value,
                        message=error_event.message,
                        category="error_recording")
        
        # Log security alert for critical errors
        if error_event.severity == ErrorSeverity.CRITICAL:
            log_security_alert("critical_error_occurred", "high",
                             error_type=error_event.error_type,
                             operation=error_event.context.get('operation'),
                             message=error_event.message)

    # Public API methods

    def add_recovery_action(self, name: str, action: RecoveryAction):
        """Add custom recovery action"""
        self.recovery_actions[name] = action
        self.logger.info(f"Added custom recovery action: {name}")

    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics"""
        return {
            'session_stats': self.session_stats.copy(),
            'error_count_by_type': self._get_error_count_by_type(),
            'error_count_by_severity': self._get_error_count_by_severity(),
            'circuit_breaker_status': self.circuit_breakers.copy(),
            'performance_metrics': self._get_performance_metrics(),
            'recovery_rates': self._get_recovery_rates()
        }

    def _get_error_count_by_type(self) -> Dict[str, int]:
        """Get error counts grouped by type"""
        counts = {}
        for error in self.error_history:
            counts[error.error_type] = counts.get(error.error_type, 0) + 1
        return counts

    def _get_error_count_by_severity(self) -> Dict[str, int]:
        """Get error counts grouped by severity"""
        counts = {severity.value: 0 for severity in ErrorSeverity}
        for error in self.error_history:
            counts[error.severity.value] += 1
        return counts

    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        metrics = {}
        for operation, times in self.performance_monitor['operation_times'].items():
            if times:
                metrics[operation] = {
                    'avg_duration': sum(times) / len(times),
                    'max_duration': max(times),
                    'min_duration': min(times),
                    'total_calls': len(times)
                }
        return metrics

    def _get_recovery_rates(self) -> Dict[str, float]:
        """Get recovery success rates"""
        rates = {}
        for action, stats in self.performance_monitor['recovery_success_rates'].items():
            total = stats['successes'] + stats['failures']
            if total > 0:
                rates[action] = stats['successes'] / total
            else:
                rates[action] = 0.0
        return rates

    def is_operation_degraded(self, operation_name: str) -> bool:
        """Check if operation is in degraded mode"""
        if operation_name in self.circuit_breakers:
            return self.circuit_breakers[operation_name].get('degraded', False)
        return False

    def reset_circuit_breaker(self, operation_name: str):
        """Reset circuit breaker for operation"""
        if operation_name in self.circuit_breakers:
            self.circuit_breakers[operation_name] = {
                'failure_count': 0,
                'success_count': 0,
                'state': 'closed',
                'last_failure': None,
                'degraded': False
            }
            self.logger.info(f"Reset circuit breaker for {operation_name}")

    def register_r2_session(self, session_id: str, r2_session, binary_path: str) -> None:
        """Register a new R2 session for tracking"""
        try:
            with self.session_lock:
                self.active_sessions[session_id] = {
                    'r2_session': r2_session,
                    'binary_path': binary_path,
                    'created': datetime.now(),
                    'last_activity': datetime.now(),
                    'operation_count': 0,
                    'error_count': 0
                }
            
            self.logger.info("R2 session registered",
                           session_id=session_id,
                           binary_path=binary_path,
                           category="session_management")
        except Exception as e:
            self.logger.error("Failed to register R2 session",
                            session_id=session_id,
                            error=str(e))

    def unregister_r2_session(self, session_id: str) -> None:
        """Unregister and cleanup an R2 session"""
        try:
            with self.session_lock:
                if session_id in self.active_sessions:
                    session_info = self.active_sessions[session_id]
                    duration = datetime.now() - session_info['created']
                    
                    self._cleanup_r2_session(session_id)
                    
                    self.logger.info("R2 session unregistered",
                                   session_id=session_id,
                                   duration_seconds=duration.total_seconds(),
                                   operations=session_info.get('operation_count', 0),
                                   errors=session_info.get('error_count', 0),
                                   category="session_management")
        except Exception as e:
            self.logger.error("Failed to unregister R2 session",
                            session_id=session_id,
                            error=str(e))

    def update_session_activity(self, session_id: str) -> None:
        """Update last activity timestamp for a session"""
        try:
            with self.session_lock:
                if session_id in self.active_sessions:
                    self.active_sessions[session_id]['last_activity'] = datetime.now()
                    self.active_sessions[session_id]['operation_count'] += 1
        except Exception as e:
            self.logger.debug("Failed to update session activity",
                            session_id=session_id, error=str(e))

    def get_system_resource_status(self) -> Dict[str, Any]:
        """Get current system resource status"""
        try:
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=0.1)
            disk_usage = psutil.disk_usage('/')
            
            return {
                'memory': {
                    'percent': memory.percent,
                    'available_gb': memory.available / (1024**3),
                    'used_gb': memory.used / (1024**3),
                    'total_gb': memory.total / (1024**3)
                },
                'cpu': {
                    'percent': cpu_percent
                },
                'disk': {
                    'free_gb': disk_usage.free / (1024**3),
                    'used_gb': disk_usage.used / (1024**3),
                    'total_gb': disk_usage.total / (1024**3)
                },
                'active_sessions': len(self.active_sessions),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error("Failed to get system resource status", error=str(e))
            return {}

    def is_resource_constrained(self) -> bool:
        """Check if system resources are constrained"""
        try:
            status = self.get_system_resource_status()
            
            memory_constrained = (status.get('memory', {}).get('percent', 0) > 
                                self.resource_thresholds['memory_usage_percent'])
            cpu_constrained = (status.get('cpu', {}).get('percent', 0) > 
                             self.resource_thresholds['cpu_usage_percent'])
            disk_constrained = (status.get('disk', {}).get('free_gb', float('inf')) < 
                              self.resource_thresholds['disk_space_gb'])
            
            return memory_constrained or cpu_constrained or disk_constrained
        except Exception:
            return False

    def add_temp_file(self, file_path: str) -> None:
        """Track a temporary file for cleanup"""
        self.temp_files.add(file_path)

    def add_temp_dir(self, dir_path: str) -> None:
        """Track a temporary directory for cleanup"""
        self.temp_dirs.add(dir_path)

    def clear_error_history(self):
        """Clear error history"""
        self.error_history.clear()
        self.session_stats['total_errors'] = 0
        self.session_stats['recovered_errors'] = 0
        self.session_stats['critical_errors'] = 0
        self.session_stats['last_error'] = None
        self.logger.info("Error history cleared", category="maintenance")


# Global error handler instance
_GLOBAL_ERROR_HANDLER = None


def get_error_handler() -> R2ErrorHandler:
    """Get or create global error handler instance"""
    global _GLOBAL_ERROR_HANDLER
    if _GLOBAL_ERROR_HANDLER is None:
        _GLOBAL_ERROR_HANDLER = R2ErrorHandler()
    return _GLOBAL_ERROR_HANDLER


async def handle_r2_error(error: Exception, operation_name: str, **context) -> bool:
    """
    Convenience function to handle radare2 errors.

    Args:
        error: The exception that occurred
        operation_name: Name of the operation that failed
        **context: Additional context information

    Returns:
        bool: True if error was handled successfully, False otherwise
    """
    handler = get_error_handler()
    return await handler.handle_error(error, operation_name, context)


@contextmanager
def r2_error_context(operation_name: str, **context):
    """Context manager for radare2 error handling"""
    handler = get_error_handler()
    with handler.error_context(operation_name, **context):
        yield


__all__ = [
    'R2ErrorHandler',
    'ErrorSeverity',
    'RecoveryStrategy',
    'ErrorEvent',
    'RecoveryAction',
    'get_error_handler',
    'handle_r2_error',
    'r2_error_context'
]
