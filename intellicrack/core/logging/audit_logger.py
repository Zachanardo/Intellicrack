"""Audit Logging Framework for Intellicrack.

Provides tamper-resistant, structured logging for all exploitation attempts
and security-sensitive operations.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import logging
import os
import platform
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from ...utils.logger import get_logger
from ...utils.secrets_manager import get_secret, set_secret

logger = get_logger(__name__)


class AuditEventType(Enum):
    """Types of auditable events in the system."""

    # Exploitation Events
    EXPLOIT_ATTEMPT = "exploit_attempt"
    EXPLOIT_SUCCESS = "exploit_success"
    EXPLOIT_FAILURE = "exploit_failure"
    PAYLOAD_GENERATION = "payload_generation"

    # VM/Container Events
    VM_START = "vm_start"
    VM_STOP = "vm_stop"
    VM_SNAPSHOT = "vm_snapshot"
    CONTAINER_START = "container_start"
    CONTAINER_STOP = "container_stop"

    # Binary Analysis Events
    BINARY_LOADED = "binary_loaded"
    PROTECTION_DETECTED = "protection_detected"
    VULNERABILITY_FOUND = "vulnerability_found"

    # Security Events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    CREDENTIAL_ACCESS = "credential_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # Tool Usage Events
    TOOL_EXECUTION = "tool_execution"
    TOOL_ERROR = "tool_error"

    # System Events
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    CONFIG_CHANGE = "config_change"
    ERROR = "error"


class AuditSeverity(Enum):
    """Severity levels for audit events."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditEvent:
    """Represents a single audit event."""

    def __init__(
        self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        description: str,
        details: dict[str, Any] | None = None,
        user: str | None = None,
        source_ip: str | None = None,
        target: str | None = None,
    ):
        """Initialize an audit event.

        Args:
            event_type: Type of the event
            severity: Severity level
            description: Human-readable description
            details: Additional event details
            user: User who triggered the event
            source_ip: Source IP address
            target: Target of the operation (file, host, etc.)

        """
        self.event_id = self._generate_event_id()
        self.timestamp = datetime.now(timezone.utc)
        self.event_type = event_type
        self.severity = severity
        self.description = description
        self.details = details or {}
        self.user = user or self._get_current_user()
        self.source_ip = source_ip or "localhost"
        self.target = target
        self.hostname = platform.node()
        self.process_id = os.getpid()

    def _generate_event_id(self) -> str:
        """Generate a unique event ID."""
        # Use timestamp + random bytes for uniqueness
        timestamp = str(time.time()).encode()
        random_bytes = os.urandom(8)
        return hashlib.sha256(timestamp + random_bytes).hexdigest()[:16]

    def _get_current_user(self) -> str:
        """Get the current system user."""
        try:
            return os.getlogin()
        except (OSError, AttributeError):
            return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary format."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "details": self.details,
            "user": self.user,
            "source_ip": self.source_ip,
            "target": self.target,
            "hostname": self.hostname,
            "process_id": self.process_id,
        }

    def to_json(self) -> str:
        """Convert event to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of the event for integrity verification."""
        # Create a stable string representation
        event_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(event_str.encode()).hexdigest()


class AuditLogger:
    """Main audit logging class with tamper-resistant features."""

    def __init__(
        self,
        log_dir: Path | None = None,
        max_file_size: int = 100 * 1024 * 1024,  # 100MB
        rotation_count: int = 10,
        enable_encryption: bool = True,
    ):
        """Initialize the audit logger.

        Args:
            log_dir: Directory for audit logs
            max_file_size: Maximum size per log file before rotation
            rotation_count: Number of rotated files to keep
            enable_encryption: Whether to encrypt log entries

        """
        self.log_dir = log_dir or self._get_default_log_dir()
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.max_file_size = max_file_size
        self.rotation_count = rotation_count
        self.enable_encryption = enable_encryption

        # Thread safety
        self._lock = threading.RLock()

        # Current log file
        self._current_file = None
        self._current_size = 0

        # Hash chain for tamper detection
        self._last_hash = self._load_last_hash()

        # Initialize encryption if enabled
        if self.enable_encryption:
            self._init_encryption()
        else:
            self._cipher = None

        # Log system start
        self.log_event(
            AuditEvent(
                event_type=AuditEventType.SYSTEM_START,
                severity=AuditSeverity.INFO,
                description="Audit logging system initialized",
            ),
        )

    def _get_default_log_dir(self) -> Path:
        """Get platform-specific audit log directory."""
        system = platform.system()

        if system == "Windows":
            base = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData"))
        else:  # Linux/macOS
            base = Path("/var/log")

        return base / "intellicrack" / "audit"

    def _init_encryption(self):
        """Initialize encryption for log entries."""
        try:
            from intellicrack.handlers.cryptography_handler import Fernet

            # Get or generate audit encryption key
            key = get_secret("AUDIT_LOG_ENCRYPTION_KEY")
            if not key:
                # Generate new key
                key = Fernet.generate_key().decode()
                set_secret("AUDIT_LOG_ENCRYPTION_KEY", key)
                logger.info("Generated new audit log encryption key")

            self._cipher = Fernet(key.encode())
        except ImportError:
            logger.warning("Cryptography not available - audit logs will not be encrypted")
            self._cipher = None

    def _load_last_hash(self) -> str | None:
        """Load the last hash from the hash chain file."""
        hash_file = self.log_dir / ".hash_chain"
        if hash_file.exists():
            try:
                return hash_file.read_text().strip()
            except Exception as e:
                logger.error(f"Failed to load hash chain: {e}")
        return None

    def _save_hash(self, hash_value: str):
        """Save hash to the hash chain file."""
        hash_file = self.log_dir / ".hash_chain"
        try:
            hash_file.write_text(hash_value)
            # Restrict permissions on Unix-like systems
            if platform.system() != "Windows":
                os.chmod(hash_file, 0o600)
        except Exception as e:
            logger.error(f"Failed to save hash chain: {e}")

    def _get_current_log_file(self) -> Path:
        """Get the current log file path."""
        date_str = datetime.now().strftime("%Y%m%d")
        return self.log_dir / f"audit_{date_str}.log"

    def _rotate_logs(self):
        """Rotate log files when size limit is reached."""
        current_file = self._get_current_log_file()

        # Find next available rotation number
        for i in range(1, self.rotation_count + 1):
            rotated_file = current_file.with_suffix(f".log.{i}")
            if not rotated_file.exists():
                current_file.rename(rotated_file)
                break
        else:
            # Remove oldest file if rotation limit reached
            oldest = current_file.with_suffix(f".log.{self.rotation_count}")
            if oldest.exists():
                oldest.unlink()

            # Shift all files
            for i in range(self.rotation_count - 1, 0, -1):
                old_file = current_file.with_suffix(f".log.{i}")
                new_file = current_file.with_suffix(f".log.{i + 1}")
                if old_file.exists():
                    old_file.rename(new_file)

            # Rename current file
            current_file.rename(current_file.with_suffix(".log.1"))

        self._current_size = 0

    def log_event(self, event: AuditEvent):
        """Log an audit event with integrity protection."""
        with self._lock:
            try:
                # Add hash chain
                if self._last_hash:
                    event.details["previous_hash"] = self._last_hash

                # Calculate event hash
                event_hash = event.calculate_hash()
                event.details["hash"] = event_hash

                # Convert to JSON
                event_json = event.to_json()

                # Encrypt if enabled
                if self._cipher:
                    event_data = self._cipher.encrypt(event_json.encode()).decode()
                    log_entry = {
                        "encrypted": True,
                        "data": event_data,
                        "timestamp": event.timestamp.isoformat(),
                    }
                    log_line = json.dumps(log_entry) + "\n"
                else:
                    log_line = event_json + "\n"

                # Write to file
                log_file = self._get_current_log_file()

                # Check if rotation needed
                if self._current_size + len(log_line) > self.max_file_size:
                    self._rotate_logs()

                # Append to log file
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(log_line)
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk

                self._current_size += len(log_line)

                # Update hash chain
                self._last_hash = event_hash
                self._save_hash(event_hash)

                # Also log to standard logger for visibility
                log_msg = f"[AUDIT] {event.severity.value.upper()}: {event.description}"
                if event.target:
                    log_msg += f" (target: {event.target})"

                if event.severity == AuditSeverity.CRITICAL:
                    logger.critical(log_msg)
                elif event.severity == AuditSeverity.HIGH:
                    logger.error(log_msg)
                elif event.severity == AuditSeverity.MEDIUM:
                    logger.warning(log_msg)
                else:
                    logger.info(log_msg)

            except Exception as e:
                logger.error(f"Failed to write audit log: {e}")

    def log_exploit_attempt(
        self,
        target: str,
        exploit_type: str,
        payload: str | None = None,
        success: bool = False,
        error: str | None = None,
    ):
        """Log an exploitation attempt."""
        event_type = AuditEventType.EXPLOIT_SUCCESS if success else AuditEventType.EXPLOIT_FAILURE
        severity = AuditSeverity.HIGH if success else AuditSeverity.MEDIUM

        details = {"exploit_type": exploit_type, "success": success}

        if payload:
            # Don't log full payload for security, just metadata
            details["payload_size"] = len(payload)
            details["payload_hash"] = hashlib.sha256(payload.encode()).hexdigest()[:16]

        if error:
            details["error"] = str(error)

        self.log_event(
            AuditEvent(
                event_type=event_type,
                severity=severity,
                description=f"Exploit attempt on {target} using {exploit_type}",
                details=details,
                target=target,
            ),
        )

    def log_binary_analysis(self, file_path: str, file_hash: str, protections: list[str], vulnerabilities: list[str]):
        """Log binary analysis results."""
        self.log_event(
            AuditEvent(
                event_type=AuditEventType.BINARY_LOADED,
                severity=AuditSeverity.INFO,
                description=f"Binary analysis completed: {Path(file_path).name}",
                details={
                    "file_hash": file_hash,
                    "protections": protections,
                    "vulnerabilities": vulnerabilities,
                    "protection_count": len(protections),
                    "vulnerability_count": len(vulnerabilities),
                },
                target=file_path,
            ),
        )

    def log_vm_operation(self, operation: str, vm_name: str, success: bool = True, error: str | None = None):
        """Log VM-related operations."""
        event_map = {
            "start": AuditEventType.VM_START,
            "stop": AuditEventType.VM_STOP,
            "snapshot": AuditEventType.VM_SNAPSHOT,
        }

        event_type = event_map.get(operation, AuditEventType.TOOL_EXECUTION)
        severity = AuditSeverity.INFO if success else AuditSeverity.MEDIUM

        details = {"success": success}
        if error:
            details["error"] = str(error)

        self.log_event(
            AuditEvent(
                event_type=event_type,
                severity=severity,
                description=f"VM operation '{operation}' on {vm_name}",
                details=details,
                target=vm_name,
            ),
        )

    def log_credential_access(self, credential_type: str, purpose: str, success: bool = True, severity: AuditSeverity = None):
        """Log credential access attempts.

        Args:
            credential_type: Type of credential being accessed
            purpose: Purpose for credential access
            success: Whether access was successful
            severity: Override default severity level (defaults to context-appropriate level)
        """
        # Determine appropriate severity level based on context
        if severity is None:
            # Lower severity for routine system initialization operations
            if any(init_term in purpose.lower() for init_term in ["initialization", "setup", "startup", "generation"]):
                severity = AuditSeverity.LOW
            # Medium severity for operational credential access
            elif any(op_term in purpose.lower() for op_term in ["retrieval", "access", "usage"]):
                severity = AuditSeverity.LOW  # Changed from MEDIUM to LOW for routine operations
            # High severity for suspicious or failure cases
            elif not success or any(warn_term in purpose.lower() for warn_term in ["failed", "unauthorized", "invalid"]):
                severity = AuditSeverity.HIGH
            else:
                severity = AuditSeverity.MEDIUM

        self.log_event(
            AuditEvent(
                event_type=AuditEventType.CREDENTIAL_ACCESS,
                severity=severity,
                description=f"Credential access: {credential_type} for {purpose}",
                details={
                    "credential_type": credential_type,
                    "purpose": purpose,
                    "success": success,
                },
            ),
        )

    def log_tool_execution(
        self,
        tool_name: str,
        command: str,
        success: bool = True,
        output: str | None = None,
        error: str | None = None,
    ):
        """Log external tool execution."""
        event_type = AuditEventType.TOOL_EXECUTION if success else AuditEventType.TOOL_ERROR
        severity = AuditSeverity.LOW if success else AuditSeverity.MEDIUM

        details = {
            "tool": tool_name,
            "command_hash": hashlib.sha256(command.encode()).hexdigest()[:16],
            "success": success,
        }

        if output and len(output) < 1000:
            details["output_preview"] = output[:200]

        if error:
            details["error"] = str(error)

        self.log_event(
            AuditEvent(
                event_type=event_type,
                severity=severity,
                description=f"Tool execution: {tool_name}",
                details=details,
            ),
        )

    def verify_log_integrity(self, log_file: Path) -> bool:
        """Verify the integrity of a log file using hash chain."""
        try:
            previous_hash = None

            with open(log_file, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue

                    try:
                        # Parse log entry
                        entry = json.loads(line)

                        # Handle encrypted entries
                        if entry.get("encrypted") and self._cipher:
                            decrypted = self._cipher.decrypt(entry["data"].encode())
                            event_data = json.loads(decrypted)
                        else:
                            event_data = entry

                        # Verify hash chain
                        if previous_hash:
                            stored_prev = event_data.get("details", {}).get("previous_hash")
                            if stored_prev != previous_hash:
                                logger.error(f"Hash chain broken at line {line_num}")
                                return False

                        # Verify event hash
                        stored_hash = event_data.get("details", {}).get("hash")
                        if stored_hash:
                            # Remove hash from data to recalculate
                            details = event_data.get("details", {}).copy()
                            details.pop("hash", None)
                            details.pop("previous_hash", None)
                            event_data["details"] = details

                            # Recalculate hash
                            calculated_hash = hashlib.sha256(
                                json.dumps(event_data, sort_keys=True).encode(),
                            ).hexdigest()

                            if calculated_hash != stored_hash:
                                logger.error(f"Hash mismatch at line {line_num}")
                                return False

                            previous_hash = stored_hash

                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON at line {line_num}")
                        return False
                    except Exception as e:
                        logger.error(f"Error verifying line {line_num}: {e}")
                        return False

            logger.info(f"Log file {log_file} integrity verified")
            return True

        except Exception as e:
            logger.error(f"Failed to verify log integrity: {e}")
            return False

    def search_events(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        event_types: list[AuditEventType] | None = None,
        severity: AuditSeverity | None = None,
        user: str | None = None,
        target: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search audit logs based on criteria."""
        results = []

        # Get all log files in time range
        log_files = sorted(self.log_dir.glob("audit_*.log*"))

        for log_file in log_files:
            try:
                with open(log_file, encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue

                        try:
                            entry = json.loads(line)

                            # Decrypt if needed
                            if entry.get("encrypted") and self._cipher:
                                decrypted = self._cipher.decrypt(entry["data"].encode())
                                event_data = json.loads(decrypted)
                            else:
                                event_data = entry

                            # Apply filters
                            event_time = datetime.fromisoformat(event_data["timestamp"])

                            if start_time and event_time < start_time:
                                continue
                            if end_time and event_time > end_time:
                                continue

                            if event_types:
                                event_type = AuditEventType(event_data["event_type"])
                                if event_type not in event_types:
                                    continue

                            if severity:
                                event_severity = AuditSeverity(event_data["severity"])
                                if event_severity != severity:
                                    continue

                            if user and event_data.get("user") != user:
                                continue

                            if target and event_data.get("target") != target:
                                continue

                            results.append(event_data)

                        except Exception as e:
                            logger.debug(f"Error parsing log entry: {e}")

            except Exception as e:
                logger.error(f"Error reading log file {log_file}: {e}")

        return results

    def generate_report(self, start_time: datetime, end_time: datetime, output_file: Path | None = None) -> str:
        """Generate an audit report for a time period."""
        events = self.search_events(start_time=start_time, end_time=end_time)

        # Group by event type
        by_type = {}
        by_severity = {}
        by_user = {}

        for event in events:
            # By type
            event_type = event["event_type"]
            by_type[event_type] = by_type.get(event_type, 0) + 1

            # By severity
            severity = event["severity"]
            by_severity[severity] = by_severity.get(severity, 0) + 1

            # By user
            user = event.get("user", "unknown")
            by_user[user] = by_user.get(user, 0) + 1

        # Generate report
        report = f"""
INTELLICRACK AUDIT REPORT
========================
Period: {start_time.isoformat()} to {end_time.isoformat()}
Total Events: {len(events)}

Events by Type:
--------------
"""
        for event_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            report += f"  {event_type}: {count}\n"

        report += """
Events by Severity:
------------------
"""
        for severity, count in sorted(by_severity.items()):
            report += f"  {severity}: {count}\n"

        report += """
Events by User:
--------------
"""
        for user, count in sorted(by_user.items(), key=lambda x: x[1], reverse=True):
            report += f"  {user}: {count}\n"

        # Add critical events detail
        critical_events = [e for e in events if e["severity"] == "critical"]
        if critical_events:
            report += f"""
Critical Events ({len(critical_events)}):
----------------------------------------
"""
            for event in critical_events:
                report += f"  [{event['timestamp']}] {event['description']}\n"

        # Save report if output file specified
        if output_file:
            output_file.write_text(report)
            logger.info(f"Audit report saved to {output_file}")

        return report


class PerformanceMonitor:
    """Monitors performance metrics and system health."""

    def __init__(self):
        """Initialize performance metrics monitor."""
        self.metrics = {}
        self.start_times = {}
        self.counters = defaultdict(int)
        self.histograms = defaultdict(list)
        self._lock = threading.RLock()

    def start_timer(self, operation: str) -> str:
        """Start timing an operation."""
        timer_id = f"{operation}_{int(time.time() * 1000000)}"
        with self._lock:
            self.start_times[timer_id] = time.time()
        return timer_id

    def end_timer(self, timer_id: str, metadata: dict = None):
        """End timing and record duration."""
        end_time = time.time()
        with self._lock:
            if timer_id in self.start_times:
                duration = end_time - self.start_times[timer_id]
                operation = timer_id.split("_")[0]

                # Record in histogram
                self.histograms[f"{operation}_duration"].append(duration)

                # Update metrics
                metric_key = f"performance.{operation}"
                if metric_key not in self.metrics:
                    self.metrics[metric_key] = {
                        "count": 0,
                        "total_time": 0,
                        "min_time": float("inf"),
                        "max_time": 0,
                        "avg_time": 0,
                    }

                metrics = self.metrics[metric_key]
                metrics["count"] += 1
                metrics["total_time"] += duration
                metrics["min_time"] = min(metrics["min_time"], duration)
                metrics["max_time"] = max(metrics["max_time"], duration)
                metrics["avg_time"] = metrics["total_time"] / metrics["count"]

                del self.start_times[timer_id]

                # Log slow operations
                if duration > 5.0:  # More than 5 seconds
                    logger.warning(f"Slow operation {operation}: {duration:.2f}s")

    def increment_counter(self, metric: str, value: int = 1, tags: dict = None):
        """Increment a counter metric."""
        with self._lock:
            metric_key = f"counter.{metric}"
            if tags:
                tag_str = "_".join(f"{k}={v}" for k, v in sorted(tags.items()))
                metric_key += f"_{tag_str}"
            self.counters[metric_key] += value

    def record_gauge(self, metric: str, value: float, tags: dict = None):
        """Record a gauge metric."""
        with self._lock:
            metric_key = f"gauge.{metric}"
            if tags:
                tag_str = "_".join(f"{k}={v}" for k, v in sorted(tags.items()))
                metric_key += f"_{tag_str}"
            self.metrics[metric_key] = {"value": value, "timestamp": time.time()}

    def get_metrics_summary(self) -> dict[str, Any]:
        """Get summary of all metrics."""
        with self._lock:
            summary = {
                "timestamp": time.time(),
                "performance_metrics": dict(self.metrics),
                "counters": dict(self.counters),
                "system_metrics": self._get_system_metrics(),
            }

            # Add percentiles for histograms
            percentiles = {}
            for hist_name, values in self.histograms.items():
                if values:
                    sorted_values = sorted(values)
                    length = len(sorted_values)
                    percentiles[hist_name] = {
                        "p50": sorted_values[int(0.5 * length)],
                        "p90": sorted_values[int(0.9 * length)],
                        "p95": sorted_values[int(0.95 * length)],
                        "p99": sorted_values[int(0.99 * length)] if length > 10 else sorted_values[-1],
                    }

            summary["percentiles"] = percentiles
            return summary

    def _get_system_metrics(self) -> dict[str, Any]:
        """Get system-level metrics."""
        try:
            from intellicrack.handlers.psutil_handler import psutil

            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count(logical=False)

            # Memory metrics
            memory = psutil.virtual_memory()

            # Disk metrics
            disk_usage = psutil.disk_usage("/")

            # Network metrics
            net_io = psutil.net_io_counters()

            return {
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count,
                    "load_avg": psutil.getloadavg() if hasattr(psutil, "getloadavg") else None,
                },
                "memory": {
                    "total_mb": memory.total // 1024 // 1024,
                    "available_mb": memory.available // 1024 // 1024,
                    "percent": memory.percent,
                    "used_mb": memory.used // 1024 // 1024,
                },
                "disk": {
                    "total_gb": disk_usage.total // 1024 // 1024 // 1024,
                    "free_gb": disk_usage.free // 1024 // 1024 // 1024,
                    "percent": (disk_usage.used / disk_usage.total) * 100,
                },
                "network": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                },
            }
        except ImportError:
            return {"error": "psutil not available for system metrics"}
        except Exception as e:
            return {"error": f"Failed to get system metrics: {e}"}

    def reset_metrics(self):
        """Reset all metrics."""
        with self._lock:
            self.metrics.clear()
            self.counters.clear()
            self.histograms.clear()
            self.start_times.clear()


class TelemetryCollector:
    """Collects and exports telemetry data."""

    def __init__(self, export_interval: int = 300):
        """Initialize telemetry collector with export settings.

        Args:
            export_interval: Seconds between telemetry exports (default 300)

        """
        self.export_interval = export_interval
        self.performance_monitor = PerformanceMonitor()
        self.audit_logger = None
        self.telemetry_data = []
        self._lock = threading.RLock()
        self._export_thread = None
        self._running = False

    def set_audit_logger(self, audit_logger: AuditLogger):
        """Set the audit logger for telemetry."""
        self.audit_logger = audit_logger

    def start_collection(self):
        """Start telemetry collection."""
        if self._running:
            return

        # Skip during testing
        if os.environ.get("INTELLICRACK_TESTING") or os.environ.get("DISABLE_BACKGROUND_THREADS"):
            logger.info("Skipping telemetry collection (testing mode)")
            return

        self._running = True
        self._export_thread = threading.Thread(target=self._export_loop, daemon=True)
        self._export_thread.start()
        logger.info("Telemetry collection started")

    def stop_collection(self):
        """Stop telemetry collection."""
        self._running = False
        if self._export_thread:
            self._export_thread.join(timeout=5)
        logger.info("Telemetry collection stopped")

    def _export_loop(self):
        """Main export loop."""
        while self._running:
            try:
                self._collect_and_export()
                time.sleep(self.export_interval)
            except Exception as e:
                logger.error(f"Telemetry export error: {e}")
                time.sleep(60)  # Wait before retrying

    def _collect_and_export(self):
        """Collect and export telemetry data."""
        try:
            # Get performance metrics
            metrics = self.performance_monitor.get_metrics_summary()

            # Add resource manager stats
            try:
                from ..resources.resource_manager import resource_manager

                resource_stats = resource_manager.get_resource_usage_stats()
                resource_health = resource_manager.health_check()
                metrics["resource_management"] = {
                    "stats": resource_stats,
                    "health": resource_health,
                }
            except Exception as e:
                logger.debug(f"Failed to get resource stats: {e}")

            # Add external tools status
            try:
                from ..config.external_tools_config import external_tools_manager

                tools_status = external_tools_manager.generate_status_report()
                metrics["external_tools"] = tools_status
            except Exception as e:
                logger.debug(f"Failed to get tools status: {e}")

            # Store telemetry data
            with self._lock:
                self.telemetry_data.append(metrics)

                # Keep only last 100 entries
                if len(self.telemetry_data) > 100:
                    self.telemetry_data = self.telemetry_data[-100:]

            # Log summary
            self._log_telemetry_summary(metrics)

        except Exception as e:
            logger.error(f"Failed to collect telemetry: {e}")

    def _log_telemetry_summary(self, metrics: dict[str, Any]):
        """Log telemetry summary."""
        try:
            system_metrics = metrics.get("system_metrics", {})

            # CPU and Memory summary
            cpu_percent = system_metrics.get("cpu", {}).get("percent", 0)
            memory_percent = system_metrics.get("memory", {}).get("percent", 0)

            # Resource counts
            resource_mgmt = metrics.get("resource_management", {})
            resource_stats = resource_mgmt.get("stats", {})
            total_resources = resource_stats.get("total_resources", 0)

            # External tools
            ext_tools = metrics.get("external_tools", {})
            available_tools = ext_tools.get("available_tools", 0)
            total_tools = ext_tools.get("total_tools", 0)

            logger.info(
                f"Telemetry: CPU={cpu_percent:.1f}% Memory={memory_percent:.1f}% "
                f"Resources={total_resources} Tools={available_tools}/{total_tools}",
            )

            # Check for alerts
            if cpu_percent > 90:
                logger.warning(f"High CPU usage detected: {cpu_percent:.1f}%")

            if memory_percent > 90:
                logger.warning(f"High memory usage detected: {memory_percent:.1f}%")

            # Resource health alerts
            resource_health = resource_mgmt.get("health", {})
            if resource_health.get("status") != "healthy":
                logger.warning(
                    f"Resource manager health: {resource_health.get('status')} - Issues: {resource_health.get('issues', [])}",
                )

        except Exception as e:
            logger.debug(f"Failed to log telemetry summary: {e}")

    def get_telemetry_history(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent telemetry history."""
        with self._lock:
            return self.telemetry_data[-limit:]

    def export_telemetry_json(self, filepath: str):
        """Export telemetry data to JSON file."""
        try:
            import json

            with self._lock:
                data = {
                    "export_timestamp": time.time(),
                    "export_interval": self.export_interval,
                    "telemetry_data": self.telemetry_data,
                }

            with open(filepath, "w") as f:
                json.dump(data, f, indent=2, default=str)

            logger.info(f"Telemetry data exported to {filepath}")

        except Exception as e:
            logger.error(f"Failed to export telemetry: {e}")


class ContextualLogger:
    """Logger with contextual information and structured logging."""

    def __init__(self, name: str, audit_logger: AuditLogger = None):
        """Initialize contextual logger.

        Args:
            name: Logger name
            audit_logger: Optional audit logger instance for security events

        """
        self.logger = logging.getLogger(name)
        self.audit_logger = audit_logger
        self.context = {}

    def set_context(self, **kwargs):
        """Set contextual information."""
        self.context.update(kwargs)

    def clear_context(self):
        """Clear contextual information."""
        self.context.clear()

    def _format_message(self, message: str) -> str:
        """Format message with context."""
        if self.context:
            context_str = " ".join(f"{k}={v}" for k, v in self.context.items())
            return f"[{context_str}] {message}"
        return message

    def debug(self, message: str, **kwargs):
        """Log debug message with context."""
        self.logger.debug(self._format_message(message), extra=kwargs)

    def info(self, message: str, **kwargs):
        """Log info message with context."""
        self.logger.info(self._format_message(message), extra=kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message with context."""
        self.logger.warning(self._format_message(message), extra=kwargs)

    def error(self, message: str, **kwargs):
        """Log error message with context."""
        self.logger.error(self._format_message(message), extra=kwargs)

        # Also audit log errors
        if self.audit_logger:
            try:
                self.audit_logger.log_security_event(
                    event_type="error",
                    severity=AuditSeverity.HIGH,
                    message=message,
                    metadata={**self.context, **kwargs},
                )
            except Exception as e:
                # Don't fail on audit logging errors, but log for debugging
                import logging

                logging.getLogger(__name__).debug(f"Audit logging error: {e}")

    def critical(self, message: str, **kwargs):
        """Log critical message with context."""
        self.logger.critical(self._format_message(message), extra=kwargs)

        # Also audit log critical errors
        if self.audit_logger:
            try:
                self.audit_logger.log_security_event(
                    event_type="critical_error",
                    severity=AuditSeverity.CRITICAL,
                    message=message,
                    metadata={**self.context, **kwargs},
                )
            except Exception as e:
                # Don't fail on audit logging errors, but log for debugging
                import logging

                logging.getLogger(__name__).debug(f"Critical audit logging error: {e}")


# Global telemetry collector
telemetry_collector = TelemetryCollector()


def get_telemetry_collector() -> TelemetryCollector:
    """Get the global telemetry collector."""
    return telemetry_collector


def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor."""
    return telemetry_collector.performance_monitor


def create_contextual_logger(name: str, **context) -> ContextualLogger:
    """Create a contextual logger with initial context."""
    logger = ContextualLogger(name)
    logger.set_context(**context)
    return logger


def setup_comprehensive_logging():
    """Setup comprehensive logging and monitoring system."""
    try:
        # Start telemetry collection
        telemetry_collector.start_collection()

        # Setup audit logger integration
        try:
            from . import get_audit_logger

            audit_logger = get_audit_logger()
            telemetry_collector.set_audit_logger(audit_logger)
        except Exception as e:
            logger.debug(f"Failed to integrate audit logger: {e}")

        logger.info("Comprehensive logging and monitoring system initialized")

    except Exception as e:
        logger.error(f"Failed to setup comprehensive logging: {e}")


# Initialize logging system on module import
try:
    setup_comprehensive_logging()
except Exception as e:
    logger.warning(f"Failed to initialize logging system: {e}")


# Global audit logger instance
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_exploit_attempt(target: str, exploit_type: str, **kwargs):
    """Convenience function to log exploit attempts."""
    get_audit_logger().log_exploit_attempt(target, exploit_type, **kwargs)


def log_binary_analysis(file_path: str, file_hash: str, protections: list[str], vulnerabilities: list[str]):
    """Convenience function to log binary analysis."""
    get_audit_logger().log_binary_analysis(file_path, file_hash, protections, vulnerabilities)


def log_vm_operation(operation: str, vm_name: str, **kwargs):
    """Convenience function to log VM operations."""
    get_audit_logger().log_vm_operation(operation, vm_name, **kwargs)


def log_credential_access(credential_type: str, purpose: str, **kwargs):
    """Convenience function to log credential access."""
    get_audit_logger().log_credential_access(credential_type, purpose, **kwargs)


def log_tool_execution(tool_name: str, command: str, **kwargs):
    """Convenience function to log tool execution."""
    get_audit_logger().log_tool_execution(tool_name, command, **kwargs)
