"""
Centralized Logging Package for Intellicrack

Provides comprehensive logging capabilities including audit logging,
centralized configuration, log aggregation, monitoring, and alerting.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

# Core centralized logging components
from .central_config import (
    CentralLoggingManager,
    LogLevel,
    LoggingConfig,
    central_logging_manager,
    configure_logging,
    get_central_logger,
    get_logging_metrics,
    set_module_log_level,
    shutdown_logging,
)

# Integration layer
from .integration import (
    PerformanceLogger,
    exploitation_logged,
    get_integrated_logger,
    initialize_logging,
    integration,
    log_binary_analysis_results,
    log_exploitation_attempt,
    log_performance_metric,
    log_security_event,
    performance_logged,
    security_logged,
    shutdown_integrated_logging,
)

# Log monitoring and alerting
from .log_monitor import (
    Alert,
    AlertSeverity,
    AlertType,
    LogMonitor,
    LogPattern,
    add_monitoring_pattern,
    get_monitoring_alerts,
    get_monitoring_status,
    log_monitor,
    start_log_monitoring,
    stop_log_monitoring,
)

# Audit logging (backward compatibility)
from .audit_logger import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    AuditSeverity,
)

# Convenience functions for common logging tasks
def setup_logging(environment: str = None, config: dict = None) -> None:
    """Set up centralized logging with optional environment and configuration."""
    initialize_logging(config)
    start_log_monitoring()

def get_logger(name: str = None) -> 'logging.Logger':
    """Get a centrally configured logger."""
    return get_integrated_logger(name)

def log_analysis_result(file_path: str, results: dict) -> None:
    """Log binary analysis results."""
    log_binary_analysis_results(file_path, results)

def log_exploit_result(target: str, exploit_type: str, success: bool = False, **kwargs) -> None:
    """Log exploitation attempt results."""
    log_exploitation_attempt(target, exploit_type, success, **kwargs)

def log_performance(operation: str, duration: float, **kwargs) -> None:
    """Log performance metrics."""
    log_performance_metric(operation, duration, **kwargs)

def log_security(event_type: str, severity: str, description: str, **kwargs) -> None:
    """Log security events."""
    log_security_event(event_type, severity, description, **kwargs)

def get_system_status() -> dict:
    """Get comprehensive logging system status."""
    return {
        'central_logging': get_logging_metrics(),
        'monitoring': get_monitoring_status(),
        'integration_initialized': integration.initialized,
    }

def cleanup_logs(days: int = 30) -> dict:
    """Clean up old logs and alerts."""
    alert_cleanup_count = log_monitor.cleanup_old_alerts(days)
    return {
        'alerts_cleaned': alert_cleanup_count,
        'cleanup_days': days,
    }

# Export all public interfaces
__all__ = [
    # Core centralized logging
    'CentralLoggingManager',
    'LogLevel', 
    'LoggingConfig',
    'central_logging_manager',
    'configure_logging',
    'get_central_logger',
    'get_logging_metrics',
    'set_module_log_level',
    'shutdown_logging',
    
    # Integration layer
    'PerformanceLogger',
    'exploitation_logged',
    'get_integrated_logger', 
    'initialize_logging',
    'integration',
    'log_binary_analysis_results',
    'log_exploitation_attempt',
    'log_performance_metric',
    'log_security_event',
    'performance_logged',
    'security_logged',
    'shutdown_integrated_logging',
    
    # Monitoring and alerting
    'Alert',
    'AlertSeverity',
    'AlertType',
    'LogMonitor',
    'LogPattern',
    'add_monitoring_pattern',
    'get_monitoring_alerts',
    'get_monitoring_status',
    'log_monitor',
    'start_log_monitoring',
    'stop_log_monitoring',
    
    # Audit logging
    'AuditEvent',
    'AuditEventType',
    'AuditLogger', 
    'AuditSeverity',
    
    # Convenience functions
    'setup_logging',
    'get_logger',
    'log_analysis_result',
    'log_exploit_result',
    'log_performance',
    'log_security',
    'get_system_status',
    'cleanup_logs',
]