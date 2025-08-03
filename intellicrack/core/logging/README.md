# Centralized Logging System

The Intellicrack centralized logging system provides comprehensive logging capabilities including audit logging, centralized configuration, log aggregation, monitoring, and alerting.

## Quick Start

```python
from intellicrack.core.logging import setup_logging, get_logger

# Initialize the centralized logging system
setup_logging()

# Get a logger and start logging
logger = get_logger(__name__)
logger.info("Application started")
```

## Core Components

### 1. Central Configuration (`central_config.py`)
- **CentralLoggingManager**: Main orchestration class
- **LoggingConfig**: Configuration management
- **LogAggregator**: Log collection and buffering
- **LogRotationManager**: Automatic log rotation

### 2. Log Monitoring (`log_monitor.py`)
- **LogMonitor**: Real-time log analysis
- **AlertSeverity**: Alert classification system
- **LogPattern**: Pattern matching for security events
- **LogMetrics**: Performance and health metrics

### 3. Integration Layer (`integration.py`)
- **LoggingIntegration**: Bridge to existing systems
- **PerformanceLogger**: Performance tracking
- **Decorators**: `@performance_logged`, `@security_logged`

### 4. Audit Logging (`audit_logger.py`)
- **AuditLogger**: Tamper-resistant security logging
- **AuditEventType**: Event classification
- **AuditSeverity**: Security event severity levels

## Configuration

### Environment-based Configuration

```python
# Development environment
setup_logging(environment="development")

# Production environment  
setup_logging(environment="production")
```

### Custom Configuration

```python
config = {
    'logging': {
        'level': 'INFO',
        'enable_file_logging': True,
        'log_directory': '/var/log/intellicrack',
        'modules': {
            'intellicrack.core': 'DEBUG',
            'intellicrack.ui': 'WARNING'
        }
    }
}
setup_logging(config=config)
```## Usage Examples

### Basic Logging

```python
from intellicrack.core.logging import get_logger

logger = get_logger("my.module")
logger.debug("Debug information")
logger.info("Application event")
logger.warning("Warning message")
logger.error("Error occurred")
logger.critical("Critical failure")
```

### Convenience Functions

```python
from intellicrack.core.logging import (
    log_analysis_result,
    log_exploit_result, 
    log_performance,
    log_security
)

# Log binary analysis results
log_analysis_result("/path/to/binary.exe", {
    "protection": "UPX",
    "architecture": "x64", 
    "entropy": 7.8,
    "suspicious_imports": ["VirtualAlloc", "WriteProcessMemory"]
})

# Log exploitation attempts
log_exploit_result("target_app", "buffer_overflow", 
                  success=True, payload_size=256)

# Log performance metrics
log_performance("binary_analysis", 2.34, file_size=1024000)

# Log security events
log_security("suspicious_activity", "HIGH", 
            "Unusual memory access pattern detected")
```

### Using Decorators

```python
from intellicrack.core.logging import performance_logged, security_logged

@performance_logged("analyze_binary")
def analyze_binary(file_path):
    # Analysis logic here
    return analysis_results

@security_logged("credential_access", "MEDIUM") 
def access_credentials():
    # Credential access logic
    return credentials
```

### System Monitoring

```python
from intellicrack.core.logging import get_system_status, cleanup_logs

# Get comprehensive system status
status = get_system_status()
print(f"Central logging active: {status['central_logging']}")
print(f"Monitoring status: {status['monitoring']}")

# Clean up old logs (default: 30 days)
cleanup_result = cleanup_logs(days=7)
print(f"Cleaned {cleanup_result['alerts_cleaned']} old alerts")
```## Configuration File Format

The system supports YAML configuration files with environment-specific settings:

```yaml
# config.yaml
default:
  logging:
    level: INFO
    enable_file_logging: true
    log_directory: ./logs
    enable_monitoring: true
    enable_aggregation: true
    aggregation:
      buffer_size: 1000
      flush_interval: 30
    rotation:
      max_size_mb: 100
      backup_count: 5

development:
  logging:
    level: DEBUG
    modules:
      intellicrack.core: DEBUG
      intellicrack.ui: INFO

production:
  logging:
    level: WARNING
    external_handlers:
      syslog:
        enabled: true
        host: log-server.company.com
      elasticsearch:
        enabled: true
        url: https://elasticsearch.company.com:9200
```

## Monitoring and Alerting

The system includes built-in monitoring for:

- **Security Events**: Suspicious activities, exploit attempts
- **Performance Issues**: Slow operations, memory usage
- **System Health**: Error rates, log volume
- **Custom Patterns**: User-defined monitoring rules

### Alert Severity Levels

- **LOW**: Informational events
- **MEDIUM**: Events requiring attention
- **HIGH**: Serious issues requiring investigation
- **CRITICAL**: Immediate action required

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Centralized Logging System              │
├─────────────────────────────────────────────────────────────┤
│  Application Code                                           │
│  ├── get_logger() ──────────────────────────────────────┐   │
│  ├── log_analysis_result() ─────────────────────────────┼─┐ │
│  ├── @performance_logged ───────────────────────────────┼─┼─┤
│  └── @security_logged ──────────────────────────────────┼─┼─┤
├─────────────────────────────────────────────────────────┼─┼─┤
│  Integration Layer (integration.py)                     │ │ │
│  ├── Performance Tracking ──────────────────────────────┼─┘ │
│  ├── Security Event Logging ────────────────────────────┼───┤
│  └── Existing System Bridge ────────────────────────────┼───┤
├─────────────────────────────────────────────────────────┼───┤
│  Central Configuration (central_config.py)             │   │
│  ├── Environment-aware Settings ────────────────────────┼───┤
│  ├── Log Aggregation ───────────────────────────────────┼───┤
│  └── Rotation Management ───────────────────────────────┼───┤
├─────────────────────────────────────────────────────────┼───┤
│  Monitoring & Alerting (log_monitor.py)                │   │
│  ├── Pattern Detection ─────────────────────────────────┼───┤
│  ├── Real-time Analysis ────────────────────────────────┼───┤
│  └── Alert Generation ──────────────────────────────────┼───┤
├─────────────────────────────────────────────────────────┼───┤
│  Audit Logging (audit_logger.py)                       │   │
│  ├── Tamper-resistant Logging ──────────────────────────┼───┤
│  ├── Security Event Classification ─────────────────────┼───┤
│  └── Chain of Custody ──────────────────────────────────┼───┤
└─────────────────────────────────────────────────────────┼───┘
                                                          │
                                                          ▼
                                                   File System
                                                   Network Logs
                                                   External Systems
```

## Thread Safety

All components are designed to be thread-safe:

- **LogAggregator**: Uses threading locks for buffer management
- **LogMonitor**: Thread-safe pattern matching and alerting
- **AuditLogger**: Synchronized writes with hash chain integrity
- **Integration**: Safe decorator usage across threads

## Performance Considerations

- **Buffered Aggregation**: Reduces I/O overhead
- **Asynchronous Processing**: Non-blocking log operations
- **Efficient Rotation**: Background rotation without service interruption
- **Memory Management**: Configurable buffer sizes and cleanup policies

## Error Handling

The system implements robust error handling:

- **Graceful Degradation**: Continues operation if components fail
- **Error Recovery**: Automatic retry and reconnection logic
- **Diagnostic Logging**: Internal errors logged to separate channel
- **Fail-safe Defaults**: Safe fallback configurations

---

For more detailed information, see the individual module documentation and the comprehensive test suite in `tests/integration/logging/`.