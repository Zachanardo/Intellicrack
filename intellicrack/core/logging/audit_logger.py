"""Audit Logging Framework for Intellicrack.

Provides tamper-resistant, structured logging for all exploitation attempts
and security-sensitive operations.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import hashlib
import json
import logging
import os
import platform
import threading
import time
from collections import defaultdict
from datetime import UTC, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, TypedDict

from ...utils.logger import get_logger


logger = get_logger(__name__)

_secrets_manager_module: object = None


def _get_secrets_manager() -> object:
    """Lazy import secrets_manager to prevent circular imports.

    Returns:
        The secrets_manager module object for accessing secret storage operations.

    """
    global _secrets_manager_module
    if _secrets_manager_module is None:
        from ...utils import secrets_manager as _imported_secrets_manager

        _secrets_manager_module = _imported_secrets_manager
    return _secrets_manager_module


def get_secret(key: str) -> object:
    """Lazy wrapper for get_secret.

    Args:
        key: Secret key to retrieve.

    Returns:
        The secret value associated with the key.

    """
    return _get_secrets_manager().get_secret(key)


def set_secret(key: str, value: object) -> object:
    """Lazy wrapper for set_secret.

    Args:
        key: Secret key to set.
        value: Secret value to store.

    Returns:
        The result of the set_secret operation.

    """
    return _get_secrets_manager().set_secret(key, value)


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
    ) -> None:
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
        self.timestamp = datetime.now(UTC)
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
        """Generate a unique event ID.

        Uses SHA-256 hash of timestamp and random bytes to create a unique
        identifier for each audit event, enabling reliable event tracking
        and correlation in logs.

        Returns:
            A 16-character hexadecimal string representing the event ID.

        """
        # Use timestamp + random bytes for uniqueness
        timestamp = str(time.time()).encode()
        random_bytes = os.urandom(8)
        return hashlib.sha256(timestamp + random_bytes).hexdigest()[:16]

    def _get_current_user(self) -> str:
        """Get the current system user.

        Attempts to retrieve the currently logged-in user name from the system.
        Falls back to environment variables (USER on Unix, USERNAME on Windows)
        if direct retrieval fails.

        Returns:
            The username of the current system user, or 'unknown' if unable
            to determine.

        """
        try:
            return os.getlogin()
        except (OSError, AttributeError):
            return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary format.

        Serializes the audit event to a dictionary with ISO format timestamps
        and enumeration values for event type and severity.

        Returns:
            Dictionary representation of the audit event with all fields.

        """
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
        """Convert event to JSON string.

        Serializes the audit event to a formatted JSON string suitable for
        file storage or transmission.

        Returns:
            JSON string representation of the audit event with 2-space indentation.

        """
        return json.dumps(self.to_dict(), indent=2)

    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of the event for integrity verification.

        Creates a deterministic hash of the event by sorting all keys before
        hashing, enabling validation that the event has not been modified.

        Returns:
            SHA-256 hexadecimal hash digest of the event data.

        """
        # Create a stable string representation
        event_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(event_str.encode()).hexdigest()


class AuditLogger:
    """Run audit logging class with tamper-resistant features."""

    def __init__(
        self,
        log_dir: Path | None = None,
        max_file_size: int = 100 * 1024 * 1024,  # 100MB
        rotation_count: int = 10,
        enable_encryption: bool = True,
    ) -> None:
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
        """Get platform-specific audit log directory.

        Returns the appropriate system directory for audit logs based on the
        operating system: PROGRAMDATA/intellicrack/audit on Windows, or
        /var/log/intellicrack/audit on Unix-like systems.

        Returns:
            Path object pointing to the platform-specific audit log directory.

        """
        system = platform.system()

        if system == "Windows":
            base = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData"))
        else:  # Linux/macOS
            base = Path("/var/log")

        return base / "intellicrack" / "audit"

    def _init_encryption(self) -> None:
        """Initialize encryption for log entries.

        Sets up Fernet symmetric encryption for audit logs using a key stored
        in the secrets manager. Generates a new key if one does not exist.
        If cryptography is unavailable, logs a warning and continues without
        encryption.

        """
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
        """Load the last hash from the hash chain file.

        Retrieves the most recent event hash from the hash chain file for
        integrity verification and hash linking.

        Returns:
            The last stored hash value, or None if the file does not exist
            or cannot be read.

        """
        hash_file = self.log_dir / ".hash_chain"
        if hash_file.exists():
            try:
                return hash_file.read_text().strip()
            except Exception as e:
                logger.error(f"Failed to load hash chain: {e}")
        return None

    def _save_hash(self, hash_value: str) -> None:
        """Save hash to the hash chain file.

        Persists the event hash to the hash chain file with restricted
        permissions (0o600) on Unix-like systems. This enables detection
        of log tampering through hash chain verification.

        Args:
            hash_value: The SHA-256 hash to save to the chain file.

        """
        hash_file = self.log_dir / ".hash_chain"
        try:
            hash_file.write_text(hash_value)
            # Restrict permissions on Unix-like systems
            if platform.system() != "Windows":
                Path(hash_file).chmod(0o600)
        except Exception as e:
            logger.error(f"Failed to save hash chain: {e}")

    def _get_current_log_file(self) -> Path:
        """Get the current log file path.

        Generates the path for the current day's audit log file using
        YYYYMMDD format in the filename.

        Returns:
            Path object for the current audit log file (audit_YYYYMMDD.log).

        """
        date_str = datetime.now().strftime("%Y%m%d")
        return self.log_dir / f"audit_{date_str}.log"

    def _rotate_logs(self) -> None:
        """Rotate log files when size limit is reached.

        Implements log rotation using numbered suffixes (audit_YYYYMMDD.log.1,
        audit_YYYYMMDD.log.2, etc.). When the rotation count is exceeded,
        the oldest file is removed and remaining files are renumbered.
        Resets the current file size counter after rotation.

        """
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

    def log_event(self, event: AuditEvent) -> None:
        """Log an audit event with integrity protection.

        Writes an audit event to the log file with tamper-detection features
        including hash chaining, optional encryption, and automatic log rotation.
        Thread-safe operation with file synchronization to disk.

        Args:
            event: The AuditEvent to log.

        """
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
    ) -> None:
        """Log an exploitation attempt.

        Records a licensing protection exploitation attempt with details about
        the target, exploit type, success/failure status, and any associated
        errors. Payload information is hashed for security rather than logged
        in full.

        Args:
            target: Target of the exploitation attempt (file path, license type).
            exploit_type: Type of exploit attempted (keygen, patcher, etc.).
            payload: Optional payload data (hashed in logs for security).
            success: Whether the exploitation attempt succeeded.
            error: Optional error message if the attempt failed.

        """
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

    def log_binary_analysis(self, file_path: str, file_hash: str, protections: list[str], vulnerabilities: list[str]) -> None:
        """Log binary analysis results.

        Records binary analysis operations including detected protections,
        identified vulnerabilities, and file metadata for tracking licensing
        protection analysis activities.

        Args:
            file_path: Path to the analyzed binary file.
            file_hash: SHA-256 or similar hash of the binary file.
            protections: List of licensing protections detected in the binary.
            vulnerabilities: List of detected vulnerabilities or bypass points.

        """
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

    def log_vm_operation(self, operation: str, vm_name: str, success: bool = True, error: str | None = None) -> None:
        """Log VM-related operations.

        Records virtual machine operations such as start, stop, and snapshot
        actions used in licensing protection analysis environments.

        Args:
            operation: Type of VM operation ('start', 'stop', 'snapshot').
            vm_name: Name identifier of the virtual machine.
            success: Whether the operation completed successfully.
            error: Optional error message if operation failed.

        """
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

    def log_credential_access(
        self,
        credential_type: str,
        purpose: str,
        success: bool = True,
        severity: AuditSeverity = None,
    ) -> None:
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
    ) -> None:
        """Log external tool execution.

        Records execution of external tools (radare2, Frida, etc.) used in
        licensing protection analysis, including command details and results.
        Output is truncated and hashed for security and privacy.

        Args:
            tool_name: Name of the external tool executed.
            command: Full command line used to invoke the tool.
            success: Whether tool execution completed successfully.
            output: Optional output from tool execution (truncated in logs).
            error: Optional error message if execution failed.

        """
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
        """Verify the integrity of a log file using hash chain.

        Validates that a log file has not been tampered with by checking the
        hash chain linkage between events. Detects both event modification
        and insertion/deletion of events.

        Args:
            log_file: Path to the audit log file to verify.

        Returns:
            True if the log file passes integrity verification, False otherwise.

        """
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

                        if stored_hash := event_data.get("details", {}).get("hash"):
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
        """Search audit logs based on criteria.

        Queries audit logs across all log files, filtering by optional time
        range, event types, severity level, user, and target. Handles both
        encrypted and plaintext log entries.

        Args:
            start_time: Earliest event timestamp to include (optional).
            end_time: Latest event timestamp to include (optional).
            event_types: List of AuditEventType values to filter by (optional).
            severity: Severity level to filter by (optional).
            user: Username to filter events by (optional).
            target: Target identifier to filter events by (optional).

        Returns:
            List of event dictionaries matching the search criteria.

        """
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
        """Generate an audit report for a time period.

        Creates a formatted text report summarizing audit activities within
        the specified time range, including event counts by type, severity,
        and user, plus details of critical events.

        Args:
            start_time: Start of the reporting period.
            end_time: End of the reporting period.
            output_file: Optional path to write the report to disk.

        Returns:
            Formatted report string with audit statistics and critical events.

        """
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

        if critical_events := [e for e in events if e["severity"] == "critical"]:
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

    def __init__(self) -> None:
        """Initialize performance metrics monitor."""
        self.metrics = {}
        self.start_times = {}
        self.counters = defaultdict(int)
        self.histograms = defaultdict(list)
        self._lock = threading.RLock()

    def start_timer(self, operation: str) -> str:
        """Start timing an operation.

        Creates a unique timer ID and records the start time for measuring
        operation duration. Timer IDs are microsecond-precision based to
        ensure uniqueness.

        Args:
            operation: Name of the operation being timed.

        Returns:
            Unique timer ID for later reference with end_timer().

        """
        timer_id = f"{operation}_{int(time.time() * 1000000)}"
        with self._lock:
            self.start_times[timer_id] = time.time()
        return timer_id

    def end_timer(self, timer_id: str, metadata: dict[str, Any] | None = None) -> None:
        """End timing and record duration.

        Completes timing for an operation, calculating elapsed time and updating
        performance metrics including percentile calculations. Logs warnings
        for operations exceeding 5 seconds.

        Args:
            timer_id: The timer ID returned by start_timer().
            metadata: Optional metadata dictionary (currently unused).

        """
        end_time = time.time()
        with self._lock:
            if timer_id in self.start_times:
                duration = end_time - self.start_times[timer_id]
                operation = timer_id.split("_", maxsplit=1)[0]

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

    def increment_counter(self, metric: str, value: int = 1, tags: dict[str, Any] | None = None) -> None:
        """Increment a counter metric.

        Updates a counter metric by a specified value, optionally tagged with
        metadata for categorization.

        Args:
            metric: Name of the counter metric.
            value: Amount to increment by (default 1).
            tags: Optional dictionary of tags for metric categorization.

        """
        with self._lock:
            metric_key = f"counter.{metric}"
            if tags:
                tag_str = "_".join(f"{k}={v}" for k, v in sorted(tags.items()))
                metric_key += f"_{tag_str}"
            self.counters[metric_key] += value

    def record_gauge(self, metric: str, value: float, tags: dict[str, Any] | None = None) -> None:
        """Record a gauge metric.

        Records a point-in-time numeric value for a gauge metric with
        timestamp, optionally tagged for categorization.

        Args:
            metric: Name of the gauge metric.
            value: Numeric value to record.
            tags: Optional dictionary of tags for metric categorization.

        """
        with self._lock:
            metric_key = f"gauge.{metric}"
            if tags:
                tag_str = "_".join(f"{k}={v}" for k, v in sorted(tags.items()))
                metric_key += f"_{tag_str}"
            self.metrics[metric_key] = {"value": value, "timestamp": time.time()}

    def get_metrics_summary(self) -> dict[str, Any]:
        """Get summary of all metrics.

        Compiles a comprehensive summary of all collected metrics including
        performance metrics, counters, system metrics, and percentile data
        for histograms.

        Returns:
            Dictionary containing performance metrics, counters, system metrics,
            and percentile distributions.

        """
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
        """Get system-level metrics.

        Collects system resource metrics including CPU, memory, disk, and
        network statistics using psutil. Returns error information if psutil
        is unavailable.

        Returns:
            Dictionary with CPU, memory, disk, and network metrics, or error
            information if metrics cannot be collected.

        """
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

    def reset_metrics(self) -> None:
        """Reset all metrics.

        Clears all accumulated metrics, counters, histograms, and active timers.
        Thread-safe operation suitable for periodic metric reset operations.

        """
        with self._lock:
            self.metrics.clear()
            self.counters.clear()
            self.histograms.clear()
            self.start_times.clear()


class TelemetryCollector:
    """Collects and exports telemetry data."""

    def __init__(self, export_interval: int = 300) -> None:
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

    def set_audit_logger(self, audit_logger: AuditLogger) -> None:
        """Set the audit logger for telemetry.

        Associates an AuditLogger instance with the telemetry collector for
        logging security events discovered during telemetry collection.

        Args:
            audit_logger: The AuditLogger instance to use.

        """
        self.audit_logger = audit_logger

    def start_collection(self) -> None:
        """Start telemetry collection.

        Begins background telemetry collection in a daemon thread. Respects
        testing mode environment variables to avoid background threads during
        unit testing.

        """
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

    def stop_collection(self) -> None:
        """Stop telemetry collection.

        Halts background telemetry collection and waits for the collection
        thread to terminate with a 5-second timeout.

        """
        self._running = False
        if self._export_thread:
            self._export_thread.join(timeout=5)
        logger.info("Telemetry collection stopped")

    def _export_loop(self) -> None:
        """Run main export loop.

        Main loop for background telemetry collection. Periodically calls
        _collect_and_export() at the configured export_interval. Continues
        until stop_collection() is called.

        """
        while self._running:
            try:
                self._collect_and_export()
                time.sleep(self.export_interval)
            except Exception as e:
                logger.error(f"Telemetry export error: {e}")
                time.sleep(60)  # Wait before retrying

    def _collect_and_export(self) -> None:
        """Collect and export telemetry data.

        Gathers performance metrics, resource statistics, and external tool
        status. Stores telemetry data internally and logs a summary. Gracefully
        handles failures in individual collection steps.

        """
        try:
            # Get performance metrics
            metrics = self.performance_monitor.get_metrics_summary()

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

    def _log_telemetry_summary(self, metrics: dict[str, Any]) -> None:
        """Log telemetry summary.

        Logs a concise summary of current system metrics and triggers alerts
        for critical resource conditions (>90% CPU or memory usage).

        Args:
            metrics: Dictionary of collected metrics.

        """
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
        """Get recent telemetry history.

        Retrieves the most recent telemetry data points up to the specified limit.

        Args:
            limit: Maximum number of recent entries to return (default 50).

        Returns:
            List of telemetry data dictionaries in reverse chronological order.

        """
        with self._lock:
            return self.telemetry_data[-limit:]

    def export_telemetry_json(self, filepath: str) -> None:
        """Export telemetry data to JSON file.

        Writes all collected telemetry data to a JSON file with metadata
        including export timestamp and interval configuration.

        Args:
            filepath: Path where the JSON telemetry export will be written.

        """
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

    def __init__(self, name: str, audit_logger: AuditLogger = None) -> None:
        """Initialize contextual logger.

        Args:
            name: Logger name
            audit_logger: Optional audit logger instance for security events

        """
        self.logger = logging.getLogger(name)
        self.audit_logger = audit_logger
        self.context = {}

    def set_context(self, **kwargs: object) -> None:
        """Set contextual information.

        Args:
            **kwargs: Key-value pairs of context information to set.

        """
        self.context.update(kwargs)

    def clear_context(self) -> None:
        """Clear contextual information.

        Removes all contextual key-value pairs from the logger. Subsequent
        log messages will not include context information.

        """
        self.context.clear()

    def _format_message(self, message: str) -> str:
        """Format message with context.

        Prepends contextual information to log messages in square brackets
        if context is available.

        Args:
            message: The message to format.

        Returns:
            Formatted message with context prefix, or original message if no context.

        """
        if self.context:
            context_str = " ".join(f"{k}={v}" for k, v in self.context.items())
            return f"[{context_str}] {message}"
        return message

    def debug(self, message: str, **kwargs: object) -> None:
        """Log debug message with context.

        Args:
            message: The debug message to log.
            **kwargs: Additional context key-value pairs.

        """
        self.logger.debug(self._format_message(message), extra=kwargs)

    def info(self, message: str, **kwargs: object) -> None:
        """Log info message with context.

        Args:
            message: The info message to log.
            **kwargs: Additional context key-value pairs.

        """
        self.logger.info(self._format_message(message), extra=kwargs)

    def warning(self, message: str, **kwargs: object) -> None:
        """Log warning message with context.

        Args:
            message: The warning message to log.
            **kwargs: Additional context key-value pairs.

        """
        self.logger.warning(self._format_message(message), extra=kwargs)

    def error(self, message: str, **kwargs: object) -> None:
        """Log error message with context.

        Args:
            message: The error message to log.
            **kwargs: Additional context key-value pairs.

        """
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

    def critical(self, message: str, **kwargs: object) -> None:
        """Log critical message with context.

        Args:
            message: The critical message to log.
            **kwargs: Additional context key-value pairs.

        """
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


telemetry_collector: TelemetryCollector = TelemetryCollector()


def get_telemetry_collector() -> TelemetryCollector:
    """Get the global telemetry collector instance.

    Returns:
        The singleton TelemetryCollector instance for system-wide telemetry collection.

    """
    return telemetry_collector


def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor instance.

    Returns:
        The PerformanceMonitor associated with the global telemetry collector.

    """
    return telemetry_collector.performance_monitor


def create_contextual_logger(name: str, **context: object) -> ContextualLogger:
    """Create a contextual logger with initial context.

    Args:
        name: Logger name.
        **context: Initial context key-value pairs.

    Returns:
        A new ContextualLogger instance with the provided context.

    """
    logger = ContextualLogger(name)
    logger.set_context(**context)
    return logger


def setup_comprehensive_logging() -> None:
    """Set up comprehensive logging and monitoring system.

    Initializes the global telemetry collector, starts performance monitoring,
    and integrates the audit logger for security event tracking. This function
    should be called explicitly from the main application to avoid circular
    import issues during module initialization.

    Raises:
        Exception: Logs errors during setup but does not raise.

    """
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


# Note: Call setup_comprehensive_logging() explicitly from main application
# to avoid circular import issues during module initialization


_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance.

    Creates and returns the singleton AuditLogger instance for system-wide
    audit event logging. The logger is initialized on first access with
    default settings including encryption if available.

    Returns:
        The singleton AuditLogger instance for logging security events.

    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_exploit_attempt(target: str, exploit_type: str, **kwargs: object) -> None:
    """Log exploit attempts.

    Args:
        target: Target of the exploit attempt.
        exploit_type: Type of exploit attempted.
        **kwargs: Additional context for the exploit attempt.

    """
    get_audit_logger().log_exploit_attempt(target, exploit_type, **kwargs)


def log_binary_analysis(file_path: str, file_hash: str, protections: list[str], vulnerabilities: list[str]) -> None:
    """Log binary analysis.

    Args:
        file_path: Path to the analyzed binary file.
        file_hash: Hash of the binary file.
        protections: List of protections detected in the binary.
        vulnerabilities: List of vulnerabilities found in the binary.

    """
    get_audit_logger().log_binary_analysis(file_path, file_hash, protections, vulnerabilities)


def log_vm_operation(operation: str, vm_name: str, **kwargs: object) -> None:
    """Log VM operations.

    Args:
        operation: Type of VM operation (start, stop, snapshot, etc.).
        vm_name: Name of the virtual machine.
        **kwargs: Additional context for the VM operation.

    """
    get_audit_logger().log_vm_operation(operation, vm_name, **kwargs)


def log_credential_access(credential_type: str, purpose: str, **kwargs: object) -> None:
    """Log credential access.

    Args:
        credential_type: Type of credential being accessed.
        purpose: Purpose for the credential access.
        **kwargs: Additional context for the credential access event.

    """
    get_audit_logger().log_credential_access(credential_type, purpose, **kwargs)


def log_tool_execution(tool_name: str, command: str, **kwargs: object) -> None:
    """Log tool execution.

    Args:
        tool_name: Name of the tool being executed.
        command: Command line used to execute the tool.
        **kwargs: Additional context for the tool execution.

    """
    get_audit_logger().log_tool_execution(tool_name, command, **kwargs)
