"""
Log Monitoring and Alerting System for Intellicrack

This module provides real-time log monitoring, pattern detection,
and alerting capabilities for the centralized logging system.

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
import re
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Pattern, Set

from .central_config import LogLevel


class AlertSeverity(Enum):
    """Alert severity levels."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of alerts that can be generated."""
    
    ERROR_RATE = "error_rate"
    PATTERN_MATCH = "pattern_match"
    THRESHOLD_BREACH = "threshold_breach"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    SECURITY_EVENT = "security_event"
    SYSTEM_HEALTH = "system_health"


class LogPattern:
    """Defines a log pattern to monitor."""
    
    def __init__(self, name: str, pattern: str, severity: AlertSeverity,
                 description: str, action: Optional[str] = None):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.severity = severity
        self.description = description
        self.action = action
        self.match_count = 0
        self.last_match = None
        self.created_at = datetime.now()
    
    def matches(self, message: str) -> bool:
        """Check if message matches this pattern."""
        match = self.pattern.search(message)
        if match:
            self.match_count += 1
            self.last_match = datetime.now()
            return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert pattern to dictionary."""
        return {
            'name': self.name,
            'severity': self.severity.value,
            'description': self.description,
            'action': self.action,
            'match_count': self.match_count,
            'last_match': self.last_match.isoformat() if self.last_match else None,
            'created_at': self.created_at.isoformat(),
        }


class Alert:
    """Represents a monitoring alert."""
    
    def __init__(self, alert_type: AlertType, severity: AlertSeverity,
                 title: str, message: str, source: str,
                 metadata: Optional[Dict[str, Any]] = None):
        self.id = self._generate_id()
        self.alert_type = alert_type
        self.severity = severity
        self.title = title
        self.message = message
        self.source = source
        self.metadata = metadata or {}
        self.timestamp = datetime.now()
        self.acknowledged = False
        self.resolved = False
        self.resolution_note = None
    
    def _generate_id(self) -> str:
        """Generate unique alert ID."""
        import hashlib
        content = f"{time.time()}_{threading.current_thread().ident}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def acknowledge(self, note: Optional[str] = None) -> None:
        """Acknowledge the alert."""
        self.acknowledged = True
        if note:
            self.metadata['acknowledgment_note'] = note
        self.metadata['acknowledged_at'] = datetime.now().isoformat()
    
    def resolve(self, note: Optional[str] = None) -> None:
        """Resolve the alert."""
        self.resolved = True
        self.resolution_note = note
        self.metadata['resolved_at'] = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            'id': self.id,
            'alert_type': self.alert_type.value,
            'severity': self.severity.value,
            'title': self.title,
            'message': self.message,
            'source': self.source,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat(),
            'acknowledged': self.acknowledged,
            'resolved': self.resolved,
            'resolution_note': self.resolution_note,
        }


class LogMetrics:
    """Tracks log metrics for monitoring."""
    
    def __init__(self, window_size: int = 300):  # 5 minutes
        self.window_size = window_size
        self.log_counts = defaultdict(lambda: deque())
        self.error_counts = defaultdict(lambda: deque())
        self.performance_metrics = defaultdict(lambda: deque())
        self.last_cleanup = time.time()
        self._lock = threading.RLock()
    
    def record_log(self, level: str, logger_name: str, timestamp: float) -> None:
        """Record a log entry."""
        with self._lock:
            self.log_counts[logger_name].append((timestamp, level))
            
            if level in ['ERROR', 'CRITICAL']:
                self.error_counts[logger_name].append(timestamp)
            
            self._cleanup_old_entries()
    
    def record_performance(self, operation: str, duration: float, timestamp: float) -> None:
        """Record a performance metric."""
        with self._lock:
            self.performance_metrics[operation].append((timestamp, duration))
            self._cleanup_old_entries()
    
    def get_error_rate(self, logger_name: str, window_seconds: int = 60) -> float:
        """Get error rate for a logger over time window."""
        with self._lock:
            current_time = time.time()
            cutoff_time = current_time - window_seconds
            
            errors = self.error_counts.get(logger_name, deque())
            recent_errors = sum(1 for ts in errors if ts >= cutoff_time)
            
            logs = self.log_counts.get(logger_name, deque())
            recent_logs = sum(1 for ts, level in logs if ts >= cutoff_time)
            
            if recent_logs == 0:
                return 0.0
            
            return recent_errors / recent_logs
    
    def get_log_rate(self, logger_name: str, window_seconds: int = 60) -> float:
        """Get log rate for a logger (logs per second)."""
        with self._lock:
            current_time = time.time()
            cutoff_time = current_time - window_seconds
            
            logs = self.log_counts.get(logger_name, deque())
            recent_count = sum(1 for ts, level in logs if ts >= cutoff_time)
            
            return recent_count / window_seconds
    
    def get_performance_stats(self, operation: str, window_seconds: int = 300) -> Dict[str, float]:
        """Get performance statistics for an operation."""
        with self._lock:
            current_time = time.time()
            cutoff_time = current_time - window_seconds
            
            metrics = self.performance_metrics.get(operation, deque())
            recent_metrics = [duration for ts, duration in metrics if ts >= cutoff_time]
            
            if not recent_metrics:
                return {'count': 0, 'avg': 0, 'min': 0, 'max': 0, 'p95': 0}
            
            recent_metrics.sort()
            count = len(recent_metrics)
            
            return {
                'count': count,
                'avg': sum(recent_metrics) / count,
                'min': recent_metrics[0],
                'max': recent_metrics[-1],
                'p95': recent_metrics[int(0.95 * count)] if count > 10 else recent_metrics[-1],
            }
    
    def _cleanup_old_entries(self) -> None:
        """Clean up old metric entries."""
        current_time = time.time()
        
        # Only cleanup every 30 seconds to avoid overhead
        if current_time - self.last_cleanup < 30:
            return
        
        cutoff_time = current_time - self.window_size
        
        # Clean log counts
        for logger_name in list(self.log_counts.keys()):
            entries = self.log_counts[logger_name]
            while entries and entries[0][0] < cutoff_time:
                entries.popleft()
            
            if not entries:
                del self.log_counts[logger_name]
        
        # Clean error counts
        for logger_name in list(self.error_counts.keys()):
            entries = self.error_counts[logger_name]
            while entries and entries[0] < cutoff_time:
                entries.popleft()
            
            if not entries:
                del self.error_counts[logger_name]
        
        # Clean performance metrics
        for operation in list(self.performance_metrics.keys()):
            entries = self.performance_metrics[operation]
            while entries and entries[0][0] < cutoff_time:
                entries.popleft()
            
            if not entries:
                del self.performance_metrics[operation]
        
        self.last_cleanup = current_time
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        with self._lock:
            summary = {
                'active_loggers': len(self.log_counts),
                'active_operations': len(self.performance_metrics),
                'total_log_entries': sum(len(entries) for entries in self.log_counts.values()),
                'total_error_entries': sum(len(entries) for entries in self.error_counts.values()),
                'window_size': self.window_size,
                'last_cleanup': self.last_cleanup,
            }
            
            # Top loggers by activity
            logger_activity = []
            for logger_name, entries in self.log_counts.items():
                logger_activity.append((logger_name, len(entries)))
            
            logger_activity.sort(key=lambda x: x[1], reverse=True)
            summary['top_loggers'] = logger_activity[:10]
            
            return summary


class AlertHandler(ABC):
    """Base class for alert handlers."""
    
    @abstractmethod
    def handle_alert(self, alert: Alert) -> None:
        """Handle an alert."""
        pass
    
    def can_handle(self, alert: Alert) -> bool:
        """Check if this handler can handle the alert."""
        return True


class LogAlertHandler(AlertHandler):
    """Logs alerts to the logging system."""
    
    def __init__(self):
        self.logger = logging.getLogger('intellicrack.monitoring.alerts')
    
    def handle_alert(self, alert: Alert) -> None:
        """Log the alert."""
        log_method = {
            AlertSeverity.LOW: self.logger.info,
            AlertSeverity.MEDIUM: self.logger.warning,
            AlertSeverity.HIGH: self.logger.error,
            AlertSeverity.CRITICAL: self.logger.critical,
        }.get(alert.severity, self.logger.info)
        
        log_method(f"ALERT [{alert.alert_type.value}]: {alert.title} - {alert.message}")


class FileAlertHandler(AlertHandler):
    """Writes alerts to a file."""
    
    def __init__(self, alert_file: str):
        self.alert_file = alert_file
        self.lock = threading.RLock()
    
    def handle_alert(self, alert: Alert) -> None:
        """Write alert to file."""
        import json
        
        with self.lock:
            try:
                with open(self.alert_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(alert.to_dict()) + '\n')
            except Exception as e:
                # Fallback to logging
                logger = logging.getLogger('intellicrack.monitoring.alerts')
                logger.error(f"Failed to write alert to file: {e}")


class EmailAlertHandler(AlertHandler):
    """Sends alerts via email."""
    
    def __init__(self, smtp_server: str, smtp_port: int, username: str,
                 password: str, recipients: List[str], sender: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.recipients = recipients
        self.sender = sender
    
    def handle_alert(self, alert: Alert) -> None:
        """Send alert via email."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart()
            msg['From'] = self.sender
            msg['To'] = ', '.join(self.recipients)
            msg['Subject'] = f"Intellicrack Alert: {alert.title}"
            
            body = f"""
Alert Details:
- Type: {alert.alert_type.value}
- Severity: {alert.severity.value}
- Source: {alert.source}
- Timestamp: {alert.timestamp}
- Message: {alert.message}

Metadata:
{alert.metadata}
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            
        except Exception as e:
            # Fallback to logging
            logger = logging.getLogger('intellicrack.monitoring.alerts')
            logger.error(f"Failed to send email alert: {e}")
    
    def can_handle(self, alert: Alert) -> bool:
        """Only handle high severity alerts via email."""
        return alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]


class LogMonitor:
    """Main log monitoring system."""
    
    def __init__(self):
        self.patterns = {}
        self.alerts = {}
        self.alert_handlers = []
        self.metrics = LogMetrics()
        self.monitoring_thread = None
        self.running = False
        self.lock = threading.RLock()
        
        # Configuration
        self.error_rate_threshold = 0.1  # 10% error rate
        self.log_rate_threshold = 100    # 100 logs per second
        self.performance_threshold = 5.0  # 5 seconds
        
        self._setup_default_patterns()
        self._setup_default_handlers()
    
    def _setup_default_patterns(self) -> None:
        """Set up default monitoring patterns."""
        default_patterns = [
            LogPattern(
                "critical_error",
                r"CRITICAL|FATAL|EMERGENCY",
                AlertSeverity.CRITICAL,
                "Critical error detected in logs"
            ),
            LogPattern(
                "security_violation",
                r"security|breach|unauthorized|forbidden|access.denied",
                AlertSeverity.HIGH,
                "Security-related event detected"
            ),
            LogPattern(
                "memory_error",
                r"out.of.memory|memory.error|allocation.failed",
                AlertSeverity.HIGH,
                "Memory-related error detected"
            ),
            LogPattern(
                "connection_error",
                r"connection.refused|timeout|network.error|connection.lost",
                AlertSeverity.MEDIUM,
                "Network connectivity issue detected"
            ),
            LogPattern(
                "performance_warning",
                r"slow|timeout|performance|latency|bottleneck",
                AlertSeverity.MEDIUM,
                "Performance issue detected"
            ),
            LogPattern(
                "exploit_attempt",
                r"exploit|payload|shellcode|injection|bypass",
                AlertSeverity.HIGH,
                "Exploitation activity detected"
            ),
        ]
        
        for pattern in default_patterns:
            self.add_pattern(pattern)
    
    def _setup_default_handlers(self) -> None:
        """Set up default alert handlers."""
        self.add_handler(LogAlertHandler())
    
    def add_pattern(self, pattern: LogPattern) -> None:
        """Add a monitoring pattern."""
        with self.lock:
            self.patterns[pattern.name] = pattern
    
    def remove_pattern(self, name: str) -> None:
        """Remove a monitoring pattern."""
        with self.lock:
            self.patterns.pop(name, None)
    
    def add_handler(self, handler: AlertHandler) -> None:
        """Add an alert handler."""
        with self.lock:
            self.alert_handlers.append(handler)
    
    def remove_handler(self, handler: AlertHandler) -> None:
        """Remove an alert handler."""
        with self.lock:
            if handler in self.alert_handlers:
                self.alert_handlers.remove(handler)
    
    def start_monitoring(self) -> None:
        """Start log monitoring."""
        if self.running:
            return
        
        self.running = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name="LogMonitor"
        )
        self.monitoring_thread.start()
    
    def stop_monitoring(self) -> None:
        """Stop log monitoring."""
        self.running = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
    
    def process_log_record(self, record: logging.LogRecord) -> None:
        """Process a log record for monitoring."""
        timestamp = record.created
        message = record.getMessage()
        
        # Record metrics
        self.metrics.record_log(record.levelname, record.name, timestamp)
        
        # Check patterns
        with self.lock:
            for pattern in self.patterns.values():
                if pattern.matches(message):
                    self._create_alert(
                        AlertType.PATTERN_MATCH,
                        pattern.severity,
                        f"Pattern '{pattern.name}' matched",
                        f"Log message matched pattern: {pattern.description}",
                        record.name,
                        {
                            'pattern_name': pattern.name,
                            'log_level': record.levelname,
                            'log_message': message,
                            'log_module': getattr(record, 'module', record.name),
                        }
                    )
    
    def process_performance_metric(self, operation: str, duration: float) -> None:
        """Process a performance metric."""
        timestamp = time.time()
        self.metrics.record_performance(operation, duration, timestamp)
        
        # Check for performance issues
        if duration > self.performance_threshold:
            self._create_alert(
                AlertType.PERFORMANCE_DEGRADATION,
                AlertSeverity.MEDIUM,
                f"Slow operation: {operation}",
                f"Operation '{operation}' took {duration:.2f} seconds",
                "performance_monitor",
                {
                    'operation': operation,
                    'duration': duration,
                    'threshold': self.performance_threshold,
                }
            )
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self.running:
            try:
                self._check_metrics()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger = logging.getLogger('intellicrack.monitoring')
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)
    
    def _check_metrics(self) -> None:
        """Check metrics for threshold breaches."""
        # Check error rates
        for logger_name in list(self.metrics.log_counts.keys()):
            error_rate = self.metrics.get_error_rate(logger_name)
            if error_rate > self.error_rate_threshold:
                self._create_alert(
                    AlertType.ERROR_RATE,
                    AlertSeverity.HIGH,
                    f"High error rate: {logger_name}",
                    f"Error rate of {error_rate:.2%} exceeds threshold of {self.error_rate_threshold:.2%}",
                    logger_name,
                    {
                        'error_rate': error_rate,
                        'threshold': self.error_rate_threshold,
                        'logger': logger_name,
                    }
                )
        
        # Check log rates
        for logger_name in list(self.metrics.log_counts.keys()):
            log_rate = self.metrics.get_log_rate(logger_name)
            if log_rate > self.log_rate_threshold:
                self._create_alert(
                    AlertType.THRESHOLD_BREACH,
                    AlertSeverity.MEDIUM,
                    f"High log rate: {logger_name}",
                    f"Log rate of {log_rate:.1f} logs/sec exceeds threshold of {self.log_rate_threshold}",
                    logger_name,
                    {
                        'log_rate': log_rate,
                        'threshold': self.log_rate_threshold,
                        'logger': logger_name,
                    }
                )
    
    def _create_alert(self, alert_type: AlertType, severity: AlertSeverity,
                     title: str, message: str, source: str,
                     metadata: Optional[Dict[str, Any]] = None) -> Alert:
        """Create and process an alert."""
        alert = Alert(alert_type, severity, title, message, source, metadata)
        
        with self.lock:
            self.alerts[alert.id] = alert
            
            # Send to handlers
            for handler in self.alert_handlers:
                if handler.can_handle(alert):
                    try:
                        handler.handle_alert(alert)
                    except Exception as e:
                        logger = logging.getLogger('intellicrack.monitoring')
                        logger.error(f"Error in alert handler: {e}")
        
        return alert
    
    def get_alerts(self, severity: Optional[AlertSeverity] = None,
                  unresolved_only: bool = False) -> List[Alert]:
        """Get alerts matching criteria."""
        with self.lock:
            alerts = list(self.alerts.values())
            
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            
            if unresolved_only:
                alerts = [a for a in alerts if not a.resolved]
            
            return sorted(alerts, key=lambda a: a.timestamp, reverse=True)
    
    def acknowledge_alert(self, alert_id: str, note: Optional[str] = None) -> bool:
        """Acknowledge an alert."""
        with self.lock:
            if alert_id in self.alerts:
                self.alerts[alert_id].acknowledge(note)
                return True
            return False
    
    def resolve_alert(self, alert_id: str, note: Optional[str] = None) -> bool:
        """Resolve an alert."""
        with self.lock:
            if alert_id in self.alerts:
                self.alerts[alert_id].resolve(note)
                return True
            return False
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get monitoring system status."""
        with self.lock:
            return {
                'running': self.running,
                'patterns_count': len(self.patterns),
                'handlers_count': len(self.alert_handlers),
                'alerts_count': len(self.alerts),
                'unresolved_alerts': len([a for a in self.alerts.values() if not a.resolved]),
                'metrics_summary': self.metrics.get_summary(),
                'configuration': {
                    'error_rate_threshold': self.error_rate_threshold,
                    'log_rate_threshold': self.log_rate_threshold,
                    'performance_threshold': self.performance_threshold,
                }
            }
    
    def cleanup_old_alerts(self, days: int = 30) -> int:
        """Clean up old resolved alerts."""
        cutoff_date = datetime.now() - timedelta(days=days)
        removed_count = 0
        
        with self.lock:
            alerts_to_remove = []
            for alert_id, alert in self.alerts.items():
                if alert.resolved and alert.timestamp < cutoff_date:
                    alerts_to_remove.append(alert_id)
            
            for alert_id in alerts_to_remove:
                del self.alerts[alert_id]
                removed_count += 1
        
        return removed_count


# Global instance
log_monitor = LogMonitor()


def start_log_monitoring() -> None:
    """Start log monitoring."""
    log_monitor.start_monitoring()


def stop_log_monitoring() -> None:
    """Stop log monitoring."""
    log_monitor.stop_monitoring()


def add_monitoring_pattern(name: str, pattern: str, severity: str, description: str) -> None:
    """Add a monitoring pattern."""
    severity_enum = AlertSeverity(severity.lower())
    log_pattern = LogPattern(name, pattern, severity_enum, description)
    log_monitor.add_pattern(log_pattern)


def get_monitoring_alerts(severity: Optional[str] = None, unresolved_only: bool = False) -> List[Dict[str, Any]]:
    """Get monitoring alerts."""
    severity_enum = AlertSeverity(severity.lower()) if severity else None
    alerts = log_monitor.get_alerts(severity_enum, unresolved_only)
    return [alert.to_dict() for alert in alerts]


def get_monitoring_status() -> Dict[str, Any]:
    """Get monitoring system status."""
    return log_monitor.get_monitoring_status()


# Export public interface
__all__ = [
    'AlertSeverity',
    'AlertType',
    'LogPattern',
    'Alert',
    'LogMonitor',
    'start_log_monitoring',
    'stop_log_monitoring',
    'add_monitoring_pattern',
    'get_monitoring_alerts',
    'get_monitoring_status',
    'log_monitor',
]