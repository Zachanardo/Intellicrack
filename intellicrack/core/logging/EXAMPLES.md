# Centralized Logging System - Usage Examples

This document provides practical examples of using the Intellicrack centralized logging system.

## Basic Setup Examples

### Simple Application Setup

```python
#!/usr/bin/env python3
from intellicrack.core.logging import setup_logging, get_logger

def main():
    # Initialize logging at application start
    setup_logging()
    
    # Get application logger
    logger = get_logger(__name__)
    logger.info("Application started successfully")
    
    # Your application logic here
    try:
        process_binaries()
        logger.info("Binary processing completed")
    except Exception as e:
        logger.error(f"Binary processing failed: {e}")
        raise
    
    logger.info("Application shutdown")

def process_binaries():
    logger = get_logger(__name__)
    logger.debug("Starting binary analysis")
    # Analysis logic here
    
if __name__ == "__main__":
    main()
```

### Environment-specific Setup

```python
import os
from intellicrack.core.logging import setup_logging, get_logger

# Get environment from system
environment = os.getenv('INTELLICRACK_ENV', 'development')

# Setup logging for specific environment
setup_logging(environment=environment)
logger = get_logger(__name__)

if environment == 'production':
    logger.warning("Running in production mode")
else:
    logger.debug("Running in development mode")
```

## Binary Analysis Logging

### Complete Binary Analysis Workflow

```python
from intellicrack.core.logging import (
    get_logger,
    log_analysis_result,
    performance_logged,
    security_logged
)

class BinaryAnalyzer:
    def __init__(self):
        self.logger = get_logger(__name__)
    
    @performance_logged("binary_analysis")
    def analyze_binary(self, file_path):
        """Analyze a binary file with comprehensive logging."""
        self.logger.info(f"Starting analysis of {file_path}")
        
        try:
            # Load binary
            binary_data = self._load_binary(file_path)
            self.logger.debug(f"Loaded {len(binary_data)} bytes")
            
            # Detect protections
            protections = self._detect_protections(binary_data)
            if protections:
                self.logger.warning(f"Protections detected: {protections}")
            
            # Perform analysis
            results = {
                "file_path": file_path,
                "size": len(binary_data),
                "protections": protections,
                "architecture": self._detect_architecture(binary_data),
                "entropy": self._calculate_entropy(binary_data),
                "suspicious_imports": self._find_suspicious_imports(binary_data)
            }
            
            # Log comprehensive results
            log_analysis_result(file_path, results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis failed for {file_path}: {e}")
            raise
    
    @security_logged("protection_detection", "HIGH")
    def _detect_protections(self, binary_data):
        """Detect protection schemes in binary."""
        self.logger.debug("Scanning for protection schemes")
        # Protection detection logic
        return ["UPX", "VMProtect"]
    
    def _load_binary(self, file_path):
        self.logger.debug(f"Loading binary from {file_path}")
        with open(file_path, 'rb') as f:
            return f.read()
    
    def _detect_architecture(self, binary_data):
        # Architecture detection logic
        return "x64"
    
    def _calculate_entropy(self, binary_data):
        # Entropy calculation logic
        return 7.8
    
    def _find_suspicious_imports(self, binary_data):
        # Import analysis logic
        return ["VirtualAlloc", "WriteProcessMemory"]
```## Exploitation Logging

### Exploit Development and Testing

```python
from intellicrack.core.logging import (
    get_logger,
    log_exploit_result,
    log_security,
    exploitation_logged
)

class ExploitEngine:
    def __init__(self):
        self.logger = get_logger(__name__)
    
    @exploitation_logged
    def attempt_exploit(self, target, exploit_type, payload):
        """Attempt exploitation with comprehensive logging."""
        self.logger.info(f"Attempting {exploit_type} exploit on {target}")
        
        try:
            # Prepare exploit
            prepared_payload = self._prepare_payload(payload)
            self.logger.debug(f"Prepared payload: {len(prepared_payload)} bytes")
            
            # Execute exploit
            success = self._execute_exploit(target, exploit_type, prepared_payload)
            
            # Log results
            log_exploit_result(
                target=target,
                exploit_type=exploit_type,
                success=success,
                payload_size=len(prepared_payload),
                execution_time=1.25
            )
            
            if success:
                self.logger.info(f"Exploit successful on {target}")
                log_security("exploit_success", "HIGH", 
                           f"Successfully exploited {target} using {exploit_type}")
            else:
                self.logger.warning(f"Exploit failed on {target}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Exploit attempt failed: {e}")
            log_security("exploit_error", "MEDIUM", 
                        f"Exploit attempt crashed: {str(e)}")
            return False
    
    def _prepare_payload(self, payload):
        """Prepare exploitation payload."""
        self.logger.debug("Preparing exploitation payload")
        # Payload preparation logic
        return b"prepared_payload_data"
    
    def _execute_exploit(self, target, exploit_type, payload):
        """Execute the actual exploit."""
        self.logger.debug(f"Executing {exploit_type} against {target}")
        # Exploitation logic (in controlled environment)
        return True  # Simulated success
```

## Performance Monitoring

### Performance-Critical Operations

```python
from intellicrack.core.logging import (
    performance_logged,
    log_performance,
    get_logger
)
import time

class PerformanceCriticalAnalyzer:
    def __init__(self):
        self.logger = get_logger(__name__)
    
    @performance_logged("large_binary_analysis")
    def analyze_large_binary(self, file_path):
        """Analyze large binaries with performance monitoring."""
        start_time = time.time()
        
        self.logger.info(f"Starting large binary analysis: {file_path}")
        
        # Simulated heavy processing
        self._load_and_parse(file_path)
        self._perform_deep_analysis()
        self._generate_report()
        
        total_time = time.time() - start_time
        self.logger.info(f"Analysis completed in {total_time:.2f} seconds")
        
        return "analysis_results"
    
    def _load_and_parse(self, file_path):
        """Load and parse binary file."""
        self.logger.debug("Loading binary data")
        time.sleep(0.5)  # Simulated processing time
        
        # Log individual operation performance
        log_performance("binary_load", 0.5, file_size=1024000)
    
    def _perform_deep_analysis(self):
        """Perform intensive analysis."""
        self.logger.debug("Performing deep analysis")
        time.sleep(1.0)  # Simulated processing time
        
        log_performance("deep_analysis", 1.0, complexity_score=8.5)
    
    def _generate_report(self):
        """Generate analysis report."""
        self.logger.debug("Generating analysis report")
        time.sleep(0.2)  # Simulated processing time
        
        log_performance("report_generation", 0.2, report_size=2048)
```## Security Event Monitoring

### Security-Sensitive Operations

```python
from intellicrack.core.logging import (
    security_logged,
    log_security,
    get_logger,
    AuditEventType
)

class SecurityAwareComponent:
    def __init__(self):
        self.logger = get_logger(__name__)
    
    @security_logged("credential_access", "HIGH")
    def access_system_credentials(self):
        """Access system credentials with security logging."""
        self.logger.info("Attempting to access system credentials")
        
        try:
            # Simulate credential access
            credentials = self._retrieve_credentials()
            
            log_security("credential_access_success", "HIGH", 
                        "Successfully retrieved system credentials")
                        
            return credentials
        except Exception as e:
            log_security("credential_access_failure", "CRITICAL",
                        f"Failed to access credentials: {e}")
            raise
    
    @security_logged("memory_manipulation", "MEDIUM")
    def manipulate_process_memory(self, process_id, address, data):
        """Manipulate process memory with security logging."""
        self.logger.warning(f"Manipulating memory in process {process_id}")
        
        try:
            result = self._write_memory(process_id, address, data)
            
            log_security("memory_write_success", "MEDIUM",
                        f"Successfully wrote {len(data)} bytes to {hex(address)}")
            
            return result
        except Exception as e:
            log_security("memory_write_failure", "HIGH",
                        f"Memory manipulation failed: {e}")
            raise
    
    def _retrieve_credentials(self):
        """Simulate credential retrieval."""
        return {"username": "test", "password": "test"}
    
    def _write_memory(self, process_id, address, data):
        """Simulate memory writing."""
        return len(data)
```

## Custom Configuration Examples

### Advanced Configuration Setup

```python
from intellicrack.core.logging import setup_logging, get_logger

# Custom configuration for high-security environment
security_config = {
    'logging': {
        'level': 'INFO',
        'enable_file_logging': True,
        'log_directory': '/secure/logs/intellicrack',
        'enable_monitoring': True,
        'enable_aggregation': True,
        'modules': {
            'intellicrack.core.exploitation': 'DEBUG',
            'intellicrack.core.analysis': 'INFO',
            'intellicrack.ui': 'WARNING'
        },
        'aggregation': {
            'buffer_size': 500,
            'flush_interval': 10,  # More frequent flushing
            'enable_encryption': True
        },
        'monitoring': {
            'enable_security_patterns': True,
            'enable_performance_patterns': True,
            'alert_threshold': 'MEDIUM'
        },
        'rotation': {
            'max_size_mb': 50,
            'backup_count': 10,
            'compress_backups': True
        },
        'external_handlers': {
            'syslog': {
                'enabled': True,
                'host': 'security-log-server.company.com',
                'port': 514,
                'facility': 'user'
            },
            'email_alerts': {
                'enabled': True,
                'smtp_server': 'mail.company.com',
                'recipients': ['security-team@company.com'],
                'alert_level': 'HIGH'
            }
        }
    }
}

# Apply security configuration
setup_logging(config=security_config)
logger = get_logger(__name__)
logger.info("High-security logging configuration applied")
```

## Integration with Existing Code

### Gradual Migration Example

```python
# existing_module.py - Migrating from old logging
import logging

# OLD: Direct logging module usage
old_logger = logging.getLogger(__name__)

# NEW: Use centralized logging
from intellicrack.core.logging import get_logger
logger = get_logger(__name__)

def legacy_function():
    """Example of migrating existing logging calls."""
    # OLD way
    # old_logger.info("Processing file")
    
    # NEW way - drop-in replacement
    logger.info("Processing file")
    
    # Enhanced with structured data
    logger.info("Processing file", extra={
        'file_path': '/path/to/file.exe',
        'file_size': 1024000,
        'operation': 'binary_analysis'
    })

def enhanced_function():
    """Example using new centralized features."""
    from intellicrack.core.logging import log_analysis_result
    
    # Use convenience functions for structured logging
    log_analysis_result('/path/to/file.exe', {
        'protection': 'UPX',
        'architecture': 'x64',
        'suspicious': True
    })
```

## Error Handling and Troubleshooting

### Robust Error Handling

```python
from intellicrack.core.logging import get_logger, log_security

def robust_operation():
    """Example of robust error handling with logging."""
    logger = get_logger(__name__)
    
    try:
        logger.info("Starting critical operation")
        
        # Risky operation
        result = perform_risky_operation()
        
        logger.info("Critical operation completed successfully")
        return result
        
    except FileNotFoundError as e:
        logger.error(f"Required file not found: {e}")
        log_security("file_access_error", "MEDIUM", 
                    f"Required file missing: {e}")
        raise
        
    except PermissionError as e:
        logger.error(f"Permission denied: {e}")
        log_security("permission_denied", "HIGH",
                    f"Access denied to critical resource: {e}")
        raise
        
    except Exception as e:
        logger.critical(f"Unexpected error in critical operation: {e}")
        log_security("system_error", "CRITICAL",
                    f"Unexpected system error: {e}")
        raise

def perform_risky_operation():
    """Simulate a risky operation."""
    return "operation_result"
```

## System Health Monitoring

### Health Check Implementation

```python
from intellicrack.core.logging import get_system_status, cleanup_logs, get_logger

def system_health_check():
    """Perform comprehensive system health check."""
    logger = get_logger(__name__)
    logger.info("Starting system health check")
    
    # Get comprehensive system status
    status = get_system_status()
    
    # Check central logging health
    central_status = status.get('central_logging', {})
    if central_status.get('active', False):
        logger.info("Central logging system is healthy")
    else:
        logger.warning("Central logging system may have issues")
    
    # Check monitoring status
    monitoring_status = status.get('monitoring', {})
    if monitoring_status.get('active', False):
        logger.info("Log monitoring is active")
    else:
        logger.warning("Log monitoring is not active")
    
    # Perform log cleanup
    try:
        cleanup_result = cleanup_logs(days=30)
        logger.info(f"Log cleanup completed: {cleanup_result}")
    except Exception as e:
        logger.error(f"Log cleanup failed: {e}")
    
    return status

if __name__ == "__main__":
    from intellicrack.core.logging import setup_logging
    setup_logging()
    health_status = system_health_check()
    print("System health check completed")
```

---

These examples demonstrate the key patterns and best practices for using the centralized logging system effectively across different scenarios in the Intellicrack project.