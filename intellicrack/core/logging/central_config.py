"""
Centralized Logging Configuration and Management for Intellicrack

This module provides centralized logging configuration, log aggregation,
and management functionality that integrates with the existing structured
logging system.

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
import logging.handlers
import os
import platform
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    import structlog
    HAS_STRUCTLOG = True
except ImportError:
    HAS_STRUCTLOG = False


class LogLevel:
    """Centralized log level constants."""
    
    CRITICAL = 50
    ERROR = 40
    WARNING = 30
    INFO = 20
    DEBUG = 10
    NOTSET = 0
    
    @classmethod
    def from_string(cls, level: str) -> int:
        """Convert string level to integer."""
        level_map = {
            'CRITICAL': cls.CRITICAL,
            'ERROR': cls.ERROR,
            'WARNING': cls.WARNING,
            'INFO': cls.INFO,
            'DEBUG': cls.DEBUG,
            'NOTSET': cls.NOTSET
        }
        return level_map.get(level.upper(), cls.INFO)
    
    @classmethod
    def to_string(cls, level: int) -> str:
        """Convert integer level to string."""
        level_map = {
            cls.CRITICAL: 'CRITICAL',
            cls.ERROR: 'ERROR',
            cls.WARNING: 'WARNING',
            cls.INFO: 'INFO',
            cls.DEBUG: 'DEBUG',
            cls.NOTSET: 'NOTSET'
        }
        return level_map.get(level, 'INFO')


class LoggingConfig:
    """Central logging configuration container."""
    
    def __init__(self):
        self.global_level = LogLevel.INFO
        self.console_enabled = True
        self.file_enabled = True
        self.json_format = True
        self.enable_structured = HAS_STRUCTLOG
        self.log_directory = self._get_default_log_directory()
        self.max_file_size = 50 * 1024 * 1024  # 50MB
        self.backup_count = 10
        self.retention_days = 30
        
        # Module-specific logging levels
        self.module_levels = {
            'intellicrack.ai': LogLevel.INFO,
            'intellicrack.core.analysis': LogLevel.INFO,
            'intellicrack.core.exploitation': LogLevel.WARNING,
            'intellicrack.core.network': LogLevel.INFO,
            'intellicrack.ui': LogLevel.WARNING,
            'intellicrack.utils': LogLevel.WARNING,
            'intellicrack.hexview': LogLevel.WARNING,
            'intellicrack.plugins': LogLevel.INFO,
        }
        
        # Environment-specific configurations
        self.environments = {
            'development': {
                'global_level': LogLevel.DEBUG,
                'console_enabled': True,
                'json_format': False,
                'enable_performance_logging': True,
            },
            'testing': {
                'global_level': LogLevel.WARNING,
                'console_enabled': False,
                'json_format': True,
                'enable_performance_logging': False,
            },
            'production': {
                'global_level': LogLevel.INFO,
                'console_enabled': False,
                'json_format': True,
                'enable_performance_logging': True,
            }
        }
        
        # Log aggregation settings
        self.aggregation_enabled = True
        self.aggregation_interval = 300  # 5 minutes
        self.external_endpoint = None
        self.external_api_key = None
        
        # Performance logging
        self.enable_performance_logging = True
        self.performance_threshold_ms = 1000  # Log operations > 1 second
        
        # Security logging
        self.enable_security_logging = True
        self.log_sensitive_operations = True
        
        # Thread safety
        self._lock = threading.RLock()
    
    def _get_default_log_directory(self) -> Path:
        """Get platform-specific default log directory."""
        system = platform.system()
        
        if system == "Windows":
            base = Path(os.environ.get("LOCALAPPDATA", "C:\\Users\\Default\\AppData\\Local"))
            return base / "Intellicrack" / "logs"
        elif system == "Darwin":  # macOS
            base = Path.home() / "Library" / "Logs"
            return base / "Intellicrack"
        else:  # Linux and others
            if os.geteuid() == 0:  # Running as root
                return Path("/var/log/intellicrack")
            else:
                return Path.home() / ".local" / "share" / "intellicrack" / "logs"
    
    def apply_environment(self, environment: str) -> None:
        """Apply environment-specific configuration."""
        if environment not in self.environments:
            return
        
        env_config = self.environments[environment]
        
        with self._lock:
            for key, value in env_config.items():
                if hasattr(self, key):
                    setattr(self, key, value)
    
    def set_module_level(self, module: str, level: Union[int, str]) -> None:
        """Set logging level for a specific module."""
        if isinstance(level, str):
            level = LogLevel.from_string(level)
        
        with self._lock:
            self.module_levels[module] = level
    
    def get_module_level(self, module: str) -> int:
        """Get logging level for a specific module."""
        with self._lock:
            # Try exact match first
            if module in self.module_levels:
                return self.module_levels[module]
            
            # Try parent modules
            parts = module.split('.')
            for i in range(len(parts) - 1, 0, -1):
                parent = '.'.join(parts[:i])
                if parent in self.module_levels:
                    return self.module_levels[parent]
            
            return self.global_level
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        with self._lock:
            return {
                'global_level': LogLevel.to_string(self.global_level),
                'console_enabled': self.console_enabled,
                'file_enabled': self.file_enabled,
                'json_format': self.json_format,
                'enable_structured': self.enable_structured,
                'log_directory': str(self.log_directory),
                'max_file_size': self.max_file_size,
                'backup_count': self.backup_count,
                'retention_days': self.retention_days,
                'module_levels': {k: LogLevel.to_string(v) for k, v in self.module_levels.items()},
                'aggregation_enabled': self.aggregation_enabled,
                'aggregation_interval': self.aggregation_interval,
                'enable_performance_logging': self.enable_performance_logging,
                'performance_threshold_ms': self.performance_threshold_ms,
                'enable_security_logging': self.enable_security_logging,
                'log_sensitive_operations': self.log_sensitive_operations,
            }
    
    def from_dict(self, config_dict: Dict[str, Any]) -> None:
        """Load configuration from dictionary."""
        with self._lock:
            if 'global_level' in config_dict:
                self.global_level = LogLevel.from_string(config_dict['global_level'])
            
            bool_fields = ['console_enabled', 'file_enabled', 'json_format', 
                          'enable_structured', 'aggregation_enabled', 
                          'enable_performance_logging', 'enable_security_logging',
                          'log_sensitive_operations']
            
            for field in bool_fields:
                if field in config_dict:
                    setattr(self, field, config_dict[field])
            
            int_fields = ['max_file_size', 'backup_count', 'retention_days',
                         'aggregation_interval', 'performance_threshold_ms']
            
            for field in int_fields:
                if field in config_dict:
                    setattr(self, field, config_dict[field])
            
            if 'log_directory' in config_dict:
                self.log_directory = Path(config_dict['log_directory'])
            
            if 'module_levels' in config_dict:
                self.module_levels = {
                    k: LogLevel.from_string(v) 
                    for k, v in config_dict['module_levels'].items()
                }


class LogAggregator:
    """Handles log aggregation and forwarding."""
    
    def __init__(self, config: LoggingConfig):
        self.config = config
        self.buffer = []
        self.buffer_lock = threading.RLock()
        self.aggregation_thread = None
        self.running = False
        self.last_flush = time.time()
        
        # Metrics
        self.metrics = {
            'logs_processed': 0,
            'logs_forwarded': 0,
            'errors_encountered': 0,
            'last_flush_time': None,
        }
    
    def start(self) -> None:
        """Start log aggregation."""
        if self.running:
            return
        
        self.running = True
        self.aggregation_thread = threading.Thread(
            target=self._aggregation_loop,
            daemon=True,
            name="LogAggregator"
        )
        self.aggregation_thread.start()
    
    def stop(self) -> None:
        """Stop log aggregation and flush remaining logs."""
        self.running = False
        if self.aggregation_thread:
            self.aggregation_thread.join(timeout=5)
        
        # Final flush
        self._flush_buffer()
    
    def add_log_entry(self, record: logging.LogRecord) -> None:
        """Add a log entry to the aggregation buffer."""
        if not self.config.aggregation_enabled:
            return
        
        try:
            # Convert log record to structured format
            entry = {
                'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': getattr(record, 'module', record.name),
                'function': getattr(record, 'funcName', None),
                'line': getattr(record, 'lineno', None),
                'thread_id': record.thread,
                'process_id': record.process,
            }
            
            # Add exception info if present
            if record.exc_info:
                entry['exception'] = {
                    'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                    'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                    'traceback': record.exc_text,
                }
            
            # Add extra fields
            for key, value in record.__dict__.items():
                if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                              'pathname', 'filename', 'module', 'exc_info',
                              'exc_text', 'stack_info', 'lineno', 'funcName',
                              'created', 'msecs', 'relativeCreated', 'thread',
                              'threadName', 'processName', 'process', 'getMessage']:
                    entry['extra'] = entry.get('extra', {})
                    entry['extra'][key] = value
            
            with self.buffer_lock:
                self.buffer.append(entry)
                self.metrics['logs_processed'] += 1
                
                # Flush if buffer is getting large
                if len(self.buffer) >= 1000:
                    self._flush_buffer()
        
        except Exception as e:
            # Avoid infinite recursion by not logging this error
            self.metrics['errors_encountered'] += 1
    
    def _aggregation_loop(self) -> None:
        """Main aggregation loop."""
        while self.running:
            try:
                current_time = time.time()
                
                # Check if it's time to flush
                if current_time - self.last_flush >= self.config.aggregation_interval:
                    self._flush_buffer()
                
                # Sleep for a short interval
                time.sleep(1)
                
            except Exception as e:
                self.metrics['errors_encountered'] += 1
                time.sleep(5)  # Wait before retrying
    
    def _flush_buffer(self) -> None:
        """Flush the aggregation buffer."""
        with self.buffer_lock:
            if not self.buffer:
                return
            
            entries_to_flush = self.buffer.copy()
            self.buffer.clear()
        
        try:
            # Forward to external endpoint if configured
            if self.config.external_endpoint:
                self._forward_to_external(entries_to_flush)
            
            # Write to local aggregation file
            self._write_to_aggregation_file(entries_to_flush)
            
            self.metrics['logs_forwarded'] += len(entries_to_flush)
            self.metrics['last_flush_time'] = datetime.now().isoformat()
            self.last_flush = time.time()
            
        except Exception as e:
            self.metrics['errors_encountered'] += 1
            # Put entries back in buffer to retry later
            with self.buffer_lock:
                self.buffer.extend(entries_to_flush)
    
    def _forward_to_external(self, entries: List[Dict[str, Any]]) -> None:
        """Forward logs to external endpoint."""
        try:
            import requests
            
            headers = {'Content-Type': 'application/json'}
            if self.config.external_api_key:
                headers['Authorization'] = f'Bearer {self.config.external_api_key}'
            
            payload = {
                'logs': entries,
                'source': 'intellicrack',
                'timestamp': datetime.now().isoformat(),
            }
            
            response = requests.post(
                self.config.external_endpoint,
                json=payload,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
        except ImportError:
            # requests not available, skip external forwarding
            pass
        except Exception as e:
            self.metrics['errors_encountered'] += 1
            raise
    
    def _write_to_aggregation_file(self, entries: List[Dict[str, Any]]) -> None:
        """Write logs to local aggregation file."""
        aggregation_file = self.config.log_directory / "aggregated" / f"logs_{datetime.now().strftime('%Y%m%d')}.jsonl"
        aggregation_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(aggregation_file, 'a', encoding='utf-8') as f:
            for entry in entries:
                import json
                f.write(json.dumps(entry) + '\n')
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get aggregation metrics."""
        with self.buffer_lock:
            buffer_size = len(self.buffer)
        
        return {
            **self.metrics,
            'buffer_size': buffer_size,
            'running': self.running,
        }


class LogRotationManager:
    """Handles log file rotation and cleanup."""
    
    def __init__(self, config: LoggingConfig):
        self.config = config
        self.rotation_thread = None
        self.running = False
    
    def start(self) -> None:
        """Start log rotation manager."""
        if self.running:
            return
        
        self.running = True
        self.rotation_thread = threading.Thread(
            target=self._rotation_loop,
            daemon=True,
            name="LogRotationManager"
        )
        self.rotation_thread.start()
    
    def stop(self) -> None:
        """Stop log rotation manager."""
        self.running = False
        if self.rotation_thread:
            self.rotation_thread.join(timeout=5)
    
    def _rotation_loop(self) -> None:
        """Main rotation loop - runs cleanup daily."""
        while self.running:
            try:
                self._cleanup_old_logs()
                
                # Sleep for 24 hours
                for _ in range(24 * 60):  # Check every minute for 24 hours
                    if not self.running:
                        break
                    time.sleep(60)
                
            except Exception as e:
                # Continue running even if cleanup fails
                time.sleep(300)  # Wait 5 minutes before retrying
    
    def _cleanup_old_logs(self) -> None:
        """Clean up old log files based on retention policy."""
        if self.config.retention_days <= 0:
            return
        
        cutoff_date = datetime.now() - timedelta(days=self.config.retention_days)
        
        # Clean up main log files
        log_pattern = "*.log*"
        self._cleanup_directory(self.config.log_directory, cutoff_date, log_pattern)
        
        # Clean up aggregated logs
        aggregation_dir = self.config.log_directory / "aggregated"
        if aggregation_dir.exists():
            self._cleanup_directory(aggregation_dir, cutoff_date, "*.jsonl")
        
        # Clean up audit logs
        audit_dir = self.config.log_directory.parent / "audit"
        if audit_dir.exists():
            self._cleanup_directory(audit_dir, cutoff_date, "*.log*")
    
    def _cleanup_directory(self, directory: Path, cutoff_date: datetime, pattern: str) -> None:
        """Clean up files in a directory older than cutoff date."""
        try:
            for file_path in directory.glob(pattern):
                if not file_path.is_file():
                    continue
                
                # Get file modification time
                file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                
                if file_mtime < cutoff_date:
                    try:
                        file_path.unlink()
                    except Exception:
                        # Skip files that can't be deleted (might be in use)
                        continue
        
        except Exception:
            # Skip directories that can't be accessed
            pass


class CentralLogHandler(logging.Handler):
    """Custom logging handler that integrates with central logging system."""
    
    def __init__(self, config: LoggingConfig, aggregator: LogAggregator):
        super().__init__()
        self.config = config
        self.aggregator = aggregator
        
        # Set up formatter
        if config.json_format:
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                '"logger": "%(name)s", "message": %(message)s}'
            )
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        self.setFormatter(formatter)
    
    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record."""
        try:
            # Add to aggregation buffer
            self.aggregator.add_log_entry(record)
            
            # Let parent handler do the actual logging
            pass
        
        except Exception:
            self.handleError(record)


class CentralLoggingManager:
    """Central logging manager that orchestrates all logging functionality."""
    
    def __init__(self):
        self.config = LoggingConfig()
        self.aggregator = LogAggregator(self.config)
        self.rotation_manager = LogRotationManager(self.config)
        self.handlers = {}
        self.configured = False
        self._lock = threading.RLock()
    
    def configure(self, config_dict: Optional[Dict[str, Any]] = None,
                 environment: Optional[str] = None) -> None:
        """Configure the central logging system."""
        with self._lock:
            # Load configuration
            if config_dict:
                self.config.from_dict(config_dict)
            
            # Apply environment settings
            if environment:
                self.config.apply_environment(environment)
            elif 'INTELLICRACK_ENV' in os.environ:
                self.config.apply_environment(os.environ['INTELLICRACK_ENV'])
            
            # Ensure log directory exists
            self.config.log_directory.mkdir(parents=True, exist_ok=True)
            
            # Configure standard logging
            self._configure_standard_logging()
            
            # Configure structured logging if available
            if HAS_STRUCTLOG and self.config.enable_structured:
                self._configure_structured_logging()
            
            # Start background services
            if self.config.aggregation_enabled:
                self.aggregator.start()
            
            self.rotation_manager.start()
            
            self.configured = True
    
    def _configure_standard_logging(self) -> None:
        """Configure standard Python logging."""
        # Clear existing handlers
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        
        # Set root level
        root_logger.setLevel(self.config.global_level)
        
        # Console handler
        if self.config.console_enabled:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(self.config.global_level)
            
            if self.config.json_format:
                formatter = logging.Formatter(
                    '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                    '"logger": "%(name)s", "message": "%(message)s"}'
                )
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)
            self.handlers['console'] = console_handler
        
        # File handler
        if self.config.file_enabled:
            log_file = self.config.log_directory / f"intellicrack_{datetime.now().strftime('%Y%m%d')}.log"
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=self.config.max_file_size,
                backupCount=self.config.backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(self.config.global_level)
            
            if self.config.json_format:
                formatter = logging.Formatter(
                    '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                    '"logger": "%(name)s", "message": "%(message)s", '
                    '"module": "%(module)s", "function": "%(funcName)s", "line": %(lineno)d}'
                )
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - [%(module)s:%(funcName)s:%(lineno)d] - %(message)s'
                )
            
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            self.handlers['file'] = file_handler
        
        # Add central handler for aggregation
        central_handler = CentralLogHandler(self.config, self.aggregator)
        central_handler.setLevel(self.config.global_level)
        root_logger.addHandler(central_handler)
        self.handlers['central'] = central_handler
        
        # Configure module-specific levels
        for module, level in self.config.module_levels.items():
            module_logger = logging.getLogger(module)
            module_logger.setLevel(level)
    
    def _configure_structured_logging(self) -> None:
        """Configure structured logging with structlog."""
        try:
            from ...utils.structured_logging import configure_structured_logging
            
            configure_structured_logging(
                level=self.config.global_level,
                log_file=str(self.config.log_directory / f"structured_{datetime.now().strftime('%Y%m%d')}.log") if self.config.file_enabled else None,
                enable_json=self.config.json_format,
                enable_console=self.config.console_enabled,
                max_bytes=self.config.max_file_size,
                backup_count=self.config.backup_count,
            )
        
        except ImportError:
            pass
    
    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """Get a configured logger."""
        if not self.configured:
            self.configure()
        
        logger = logging.getLogger(name)
        
        # Set module-specific level if configured
        if name:
            level = self.config.get_module_level(name)
            logger.setLevel(level)
        
        return logger
    
    def set_module_level(self, module: str, level: Union[int, str]) -> None:
        """Set logging level for a specific module."""
        self.config.set_module_level(module, level)
        
        # Update existing logger
        logger = logging.getLogger(module)
        if isinstance(level, str):
            level = LogLevel.from_string(level)
        logger.setLevel(level)
    
    def get_aggregation_metrics(self) -> Dict[str, Any]:
        """Get log aggregation metrics."""
        return self.aggregator.get_metrics()
    
    def shutdown(self) -> None:
        """Shutdown the central logging system."""
        with self._lock:
            # Stop background services
            self.aggregator.stop()
            self.rotation_manager.stop()
            
            # Close handlers
            for handler in self.handlers.values():
                handler.close()
            
            self.configured = False
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()


# Global instance
central_logging_manager = CentralLoggingManager()


def configure_logging(config_dict: Optional[Dict[str, Any]] = None,
                     environment: Optional[str] = None) -> None:
    """Configure centralized logging."""
    central_logging_manager.configure(config_dict, environment)


def get_central_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a centrally configured logger."""
    return central_logging_manager.get_logger(name)


def set_module_log_level(module: str, level: Union[int, str]) -> None:
    """Set logging level for a specific module."""
    central_logging_manager.set_module_level(module, level)


def get_logging_metrics() -> Dict[str, Any]:
    """Get logging system metrics."""
    return {
        'aggregation': central_logging_manager.get_aggregation_metrics(),
        'configuration': central_logging_manager.config.to_dict(),
    }


def shutdown_logging() -> None:
    """Shutdown centralized logging."""
    central_logging_manager.shutdown()


# Export public interface
__all__ = [
    'LogLevel',
    'LoggingConfig',
    'CentralLoggingManager',
    'configure_logging',
    'get_central_logger',
    'set_module_log_level',
    'get_logging_metrics',
    'shutdown_logging',
    'central_logging_manager',
]