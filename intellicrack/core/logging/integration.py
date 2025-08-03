"""
Integration Layer for Centralized Logging System

This module provides integration between the centralized logging system
and existing Intellicrack components, ensuring seamless adoption.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import logging
import os
import time
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional

from .central_config import central_logging_manager, configure_logging, get_central_logger


class LoggingIntegration:
    """Integration layer for centralized logging."""
    
    def __init__(self):
        self.initialized = False
        self.audit_logger = None
        self.performance_tracking = {}
        
    def initialize(self, config_dict: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the integrated logging system."""
        if self.initialized:
            return
        
        # Detect environment
        environment = self._detect_environment()
        
        # Configure centralized logging
        configure_logging(config_dict, environment)
        
        # Initialize audit logging
        try:
            from .audit_logger import AuditLogger
            audit_log_dir = central_logging_manager.config.log_directory.parent / "audit"
            self.audit_logger = AuditLogger(
                log_dir=audit_log_dir,
                max_file_size=central_logging_manager.config.max_file_size,
                rotation_count=central_logging_manager.config.backup_count,
                enable_encryption=True
            )
        except Exception as e:
            logger = get_central_logger(__name__)
            logger.warning(f"Failed to initialize audit logging: {e}")
        
        # Start log monitoring
        try:
            from .log_monitor import log_monitor
            log_monitor.start_monitoring()
        except Exception as e:
            logger = get_central_logger(__name__)
            logger.warning(f"Failed to start log monitoring: {e}")
        
        # Integrate with existing loggers
        self._integrate_existing_loggers()
        
        self.initialized = True
        
        # Log successful initialization
        logger = get_central_logger(__name__)
        logger.info("Centralized logging system initialized successfully")
        
        if self.audit_logger:
            try:
                from .audit_logger import AuditEvent, AuditEventType, AuditSeverity
                self.audit_logger.log_event(
                    AuditEvent(
                        event_type=AuditEventType.SYSTEM_START,
                        severity=AuditSeverity.INFO,
                        description="Centralized logging system initialized",
                        details={
                            'environment': environment,
                            'audit_enabled': True,
                            'monitoring_enabled': True,
                        }
                    )
                )
            except Exception:
                pass
    
    def _detect_environment(self) -> str:
        """Detect the current environment."""
        # Check environment variable
        env = os.environ.get('INTELLICRACK_ENV', '').lower()
        if env in ['development', 'testing', 'production']:
            return env
        
        # Check for development indicators
        if any(indicator in os.getcwd().lower() for indicator in ['dev', 'development', 'debug']):
            return 'development'
        
        # Check for testing indicators
        if any(indicator in os.getcwd().lower() for indicator in ['test', 'testing']):
            return 'testing'
        
        # Check if running from installed location
        try:
            import sys
            if 'site-packages' in sys.executable or 'Program Files' in sys.executable:
                return 'production'
        except:
            pass
        
        # Default to development
        return 'development'
    
    def _integrate_existing_loggers(self) -> None:
        """Integrate with existing logger configurations."""
        # Set up monitoring handler
        monitoring_handler = LogMonitoringHandler()
        
        # Add to root logger
        root_logger = logging.getLogger()
        root_logger.addHandler(monitoring_handler)
        
        # Configure specific module levels based on common patterns
        module_configs = {
            'intellicrack.ai': 'INFO',
            'intellicrack.core.analysis': 'INFO', 
            'intellicrack.core.exploitation': 'WARNING',
            'intellicrack.ui': 'WARNING',
            'intellicrack.utils': 'WARNING',
        }
        
        for module, level in module_configs.items():
            central_logging_manager.set_module_level(module, level)
    
    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """Get an integrated logger."""
        if not self.initialized:
            self.initialize()
        
        return get_central_logger(name)
    
    def log_performance(self, operation: str, duration: float, **kwargs) -> None:
        """Log performance metrics."""
        if not self.initialized:
            return
        
        logger = get_central_logger('performance')
        logger.info(f"Performance: {operation} completed in {duration:.3f}s", extra={
            'operation': operation,
            'duration': duration,
            'category': 'performance',
            **kwargs
        })
        
        # Send to monitor
        try:
            from .log_monitor import log_monitor
            log_monitor.process_performance_metric(operation, duration)
        except Exception:
            pass
        
        # Audit significant operations
        if self.audit_logger and duration > 5.0:
            try:
                from .audit_logger import AuditEvent, AuditEventType, AuditSeverity
                self.audit_logger.log_event(
                    AuditEvent(
                        event_type=AuditEventType.TOOL_EXECUTION,
                        severity=AuditSeverity.MEDIUM,
                        description=f"Slow operation detected: {operation}",
                        details={
                            'operation': operation,
                            'duration': duration,
                            **kwargs
                        }
                    )
                )
            except Exception:
                pass
    
    def log_security_event(self, event_type: str, severity: str, description: str, **kwargs) -> None:
        """Log security events."""
        if not self.initialized:
            return
        
        logger = get_central_logger('security')
        log_method = getattr(logger, severity.lower(), logger.info)
        log_method(f"Security: {description}", extra={
            'event_type': event_type,
            'category': 'security',
            **kwargs
        })
        
        # Audit security events
        if self.audit_logger:
            try:
                from .audit_logger import AuditEvent, AuditEventType, AuditSeverity
                audit_severity = {
                    'info': AuditSeverity.INFO,
                    'warning': AuditSeverity.MEDIUM,
                    'error': AuditSeverity.HIGH,
                    'critical': AuditSeverity.CRITICAL,
                }.get(severity.lower(), AuditSeverity.MEDIUM)
                
                self.audit_logger.log_event(
                    AuditEvent(
                        event_type=AuditEventType.AUTH_SUCCESS if 'success' in event_type.lower() else AuditEventType.AUTH_FAILURE,
                        severity=audit_severity,
                        description=description,
                        details={
                            'event_type': event_type,
                            **kwargs
                        }
                    )
                )
            except Exception:
                pass
    
    def log_exploitation_attempt(self, target: str, exploit_type: str, success: bool = False, **kwargs) -> None:
        """Log exploitation attempts."""
        if not self.initialized:
            return
        
        logger = get_central_logger('exploitation')
        if success:
            logger.warning(f"Exploitation successful: {exploit_type} on {target}", extra={
                'target': target,
                'exploit_type': exploit_type,
                'success': success,
                'category': 'exploitation',
                **kwargs
            })
        else:
            logger.info(f"Exploitation attempt: {exploit_type} on {target}", extra={
                'target': target,
                'exploit_type': exploit_type,
                'success': success,
                'category': 'exploitation',
                **kwargs
            })
        
        # Audit exploitation attempts
        if self.audit_logger:
            self.audit_logger.log_exploit_attempt(
                target=target,
                exploit_type=exploit_type,
                success=success,
                error=kwargs.get('error'),
                payload=kwargs.get('payload')
            )
    
    def log_binary_analysis(self, file_path: str, analysis_results: Dict[str, Any]) -> None:
        """Log binary analysis results."""
        if not self.initialized:
            return
        
        logger = get_central_logger('analysis')
        logger.info(f"Binary analysis completed: {Path(file_path).name}", extra={
            'file_path': file_path,
            'category': 'analysis',
            **analysis_results
        })
        
        # Audit binary analysis
        if self.audit_logger:
            self.audit_logger.log_binary_analysis(
                file_path=file_path,
                file_hash=analysis_results.get('file_hash', ''),
                protections=analysis_results.get('protections', []),
                vulnerabilities=analysis_results.get('vulnerabilities', [])
            )
    
    def shutdown(self) -> None:
        """Shutdown the integrated logging system."""
        if not self.initialized:
            return
        
        logger = get_central_logger(__name__)
        logger.info("Shutting down centralized logging system")
        
        # Stop monitoring
        try:
            from .log_monitor import log_monitor
            log_monitor.stop_monitoring()
        except Exception:
            pass
        
        # Shutdown audit logging
        if self.audit_logger:
            try:
                from .audit_logger import AuditEvent, AuditEventType, AuditSeverity
                self.audit_logger.log_event(
                    AuditEvent(
                        event_type=AuditEventType.SYSTEM_STOP,
                        severity=AuditSeverity.INFO,
                        description="Centralized logging system shutdown"
                    )
                )
            except Exception:
                pass
        
        # Shutdown central logging
        central_logging_manager.shutdown()
        
        self.initialized = False


class LogMonitoringHandler(logging.Handler):
    """Logging handler that feeds records to the monitoring system."""
    
    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record to the monitoring system."""
        try:
            from .log_monitor import log_monitor
            log_monitor.process_log_record(record)
        except Exception:
            # Don't let monitoring failures break logging
            pass


class PerformanceLogger:
    """Context manager and decorator for performance logging."""
    
    def __init__(self, operation: str, logger_name: Optional[str] = None, **kwargs):
        self.operation = operation
        self.logger_name = logger_name
        self.kwargs = kwargs
        self.start_time = None
        
    def __enter__(self):
        """Enter context manager."""
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        if self.start_time:
            duration = time.time() - self.start_time
            integration.log_performance(self.operation, duration, **self.kwargs)
    
    def __call__(self, func):
        """Use as decorator."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            with PerformanceLogger(self.operation or func.__name__, self.logger_name, **self.kwargs):
                return func(*args, **kwargs)
        return wrapper


def performance_logged(operation: Optional[str] = None, **perf_kwargs):
    """Decorator for performance logging."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            op_name = operation or f"{func.__module__}.{func.__name__}"
            with PerformanceLogger(op_name, **perf_kwargs):
                return func(*args, **kwargs)
        return wrapper
    return decorator


def security_logged(event_type: str, severity: str = 'info'):
    """Decorator for security event logging."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                integration.log_security_event(
                    event_type=event_type,
                    severity=severity,
                    description=f"Security operation completed: {func.__name__}",
                    function=func.__name__,
                    success=True
                )
                return result
            except Exception as e:
                integration.log_security_event(
                    event_type=event_type,
                    severity='error',
                    description=f"Security operation failed: {func.__name__}",
                    function=func.__name__,
                    success=False,
                    error=str(e)
                )
                raise
        return wrapper
    return decorator


def exploitation_logged(exploit_type: str):
    """Decorator for exploitation attempt logging."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            target = kwargs.get('target', args[0] if args else 'unknown')
            try:
                result = func(*args, **kwargs)
                success = result is not None and result != False
                integration.log_exploitation_attempt(
                    target=str(target),
                    exploit_type=exploit_type,
                    success=success,
                    function=func.__name__
                )
                return result
            except Exception as e:
                integration.log_exploitation_attempt(
                    target=str(target),
                    exploit_type=exploit_type,
                    success=False,
                    function=func.__name__,
                    error=str(e)
                )
                raise
        return wrapper
    return decorator


# Global integration instance
integration = LoggingIntegration()


def initialize_logging(config_dict: Optional[Dict[str, Any]] = None) -> None:
    """Initialize integrated logging system."""
    integration.initialize(config_dict)


def get_integrated_logger(name: Optional[str] = None) -> logging.Logger:
    """Get an integrated logger."""
    return integration.get_logger(name)


def log_performance_metric(operation: str, duration: float, **kwargs) -> None:
    """Log performance metrics."""
    integration.log_performance(operation, duration, **kwargs)


def log_security_event(event_type: str, severity: str, description: str, **kwargs) -> None:
    """Log security events."""
    integration.log_security_event(event_type, severity, description, **kwargs)


def log_exploitation_attempt(target: str, exploit_type: str, success: bool = False, **kwargs) -> None:
    """Log exploitation attempts."""
    integration.log_exploitation_attempt(target, exploit_type, success, **kwargs)


def log_binary_analysis_results(file_path: str, analysis_results: Dict[str, Any]) -> None:
    """Log binary analysis results."""
    integration.log_binary_analysis(file_path, analysis_results)


def shutdown_integrated_logging() -> None:
    """Shutdown integrated logging."""
    integration.shutdown()


# Backward compatibility aliases
setup_integrated_logging = initialize_logging
get_logger = get_integrated_logger


# Export public interface
__all__ = [
    'LoggingIntegration',
    'PerformanceLogger',
    'performance_logged',
    'security_logged',
    'exploitation_logged',
    'initialize_logging',
    'get_integrated_logger',
    'log_performance_metric',
    'log_security_event',
    'log_exploitation_attempt',
    'log_binary_analysis_results',
    'shutdown_integrated_logging',
    'setup_integrated_logging',
    'get_logger',
    'integration',
]