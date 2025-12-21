"""Production tests for audit logging system.

Tests validate real event logging, hash chaining for tamper detection,
log rotation, encryption/decryption, and integrity verification.
"""

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.logging.audit_logger import AuditEvent, AuditEventType, AuditLogger, AuditSeverity


@pytest.fixture
def temp_log_dir(tmp_path: Path) -> Path:
    """Create temporary directory for audit logs."""
    log_dir = tmp_path / "audit_logs"
    log_dir.mkdir()
    return log_dir


@pytest.fixture
def audit_logger(temp_log_dir: Path) -> AuditLogger:
    """Create audit logger instance with temporary directory."""
    return AuditLogger(
        log_dir=temp_log_dir,
        max_file_size=1024,
        rotation_count=5,
        enable_encryption=False,
    )


@pytest.fixture
def encrypted_audit_logger(temp_log_dir: Path) -> AuditLogger:
    """Create audit logger with encryption enabled."""
    return AuditLogger(
        log_dir=temp_log_dir,
        max_file_size=1024,
        rotation_count=5,
        enable_encryption=True,
    )


class TestAuditEvent:
    """Test audit event creation and serialization."""

    def test_create_audit_event_with_all_fields(self) -> None:
        """Create audit event with all fields populated."""
        event = AuditEvent(
            event_type=AuditEventType.EXPLOIT_ATTEMPT,
            severity=AuditSeverity.HIGH,
            description="Test exploit attempt",
            details={"target": "test.exe", "method": "buffer_overflow"},
            user="testuser",
            source_ip="192.168.1.100",
            target="C:\\test\\target.exe",
        )

        assert event.event_type == AuditEventType.EXPLOIT_ATTEMPT
        assert event.severity == AuditSeverity.HIGH
        assert event.description == "Test exploit attempt"
        assert event.details["target"] == "test.exe"
        assert event.user == "testuser"
        assert event.source_ip == "192.168.1.100"
        assert event.target == "C:\\test\\target.exe"
        assert len(event.event_id) == 16
        assert event.process_id == os.getpid()

    def test_event_id_uniqueness(self) -> None:
        """Event IDs are unique across multiple events."""
        event1 = AuditEvent(
            event_type=AuditEventType.BINARY_LOADED,
            severity=AuditSeverity.INFO,
            description="First event",
        )

        time.sleep(0.001)

        event2 = AuditEvent(
            event_type=AuditEventType.BINARY_LOADED,
            severity=AuditSeverity.INFO,
            description="Second event",
        )

        assert event1.event_id != event2.event_id

    def test_event_to_dict_serialization(self) -> None:
        """Serialize event to dictionary with all fields."""
        event = AuditEvent(
            event_type=AuditEventType.PROTECTION_DETECTED,
            severity=AuditSeverity.MEDIUM,
            description="VMProtect detected",
            details={"protection": "VMProtect", "version": "3.5"},
        )

        event_dict = event.to_dict()

        assert event_dict["event_type"] == "protection_detected"
        assert event_dict["severity"] == "medium"
        assert event_dict["description"] == "VMProtect detected"
        assert event_dict["details"]["protection"] == "VMProtect"
        assert "timestamp" in event_dict
        assert "event_id" in event_dict

    def test_event_to_json_serialization(self) -> None:
        """Serialize event to JSON string."""
        event = AuditEvent(
            event_type=AuditEventType.VULNERABILITY_FOUND,
            severity=AuditSeverity.CRITICAL,
            description="Buffer overflow vulnerability",
        )

        json_str = event.to_json()

        parsed = json.loads(json_str)
        assert parsed["event_type"] == "vulnerability_found"
        assert parsed["severity"] == "critical"

    def test_calculate_event_hash_deterministic(self) -> None:
        """Event hash is deterministic for same event data."""
        event = AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.INFO,
            description="Radare2 execution",
        )

        hash1 = event.calculate_hash()
        hash2 = event.calculate_hash()

        assert hash1 == hash2
        assert len(hash1) == 64

    def test_event_hash_changes_with_modification(self) -> None:
        """Event hash changes when event data is modified."""
        event = AuditEvent(
            event_type=AuditEventType.CONFIG_CHANGE,
            severity=AuditSeverity.MEDIUM,
            description="Original description",
        )

        hash_before = event.calculate_hash()

        event.description = "Modified description"

        hash_after = event.calculate_hash()

        assert hash_before != hash_after


class TestAuditLogger:
    """Test audit logger functionality."""

    def test_create_audit_logger_creates_directory(self, temp_log_dir: Path) -> None:
        """Logger creates log directory if it doesn't exist."""
        new_dir = temp_log_dir / "new_logs"

        AuditLogger(log_dir=new_dir, enable_encryption=False)

        assert new_dir.exists()
        assert new_dir.is_dir()

    def test_log_single_event_writes_to_file(self, audit_logger: AuditLogger) -> None:
        """Logging event writes to file successfully."""
        event = AuditEvent(
            event_type=AuditEventType.EXPLOIT_SUCCESS,
            severity=AuditSeverity.HIGH,
            description="Successful license bypass",
            details={"method": "keygen", "target": "product.exe"},
        )

        audit_logger.log_event(event)

        log_files = list(audit_logger.log_dir.glob("audit_*.log"))
        assert log_files

        with open(log_files[0]) as f:
            content = f.read()
            assert "exploit_success" in content
            assert "Successful license bypass" in content

    def test_log_multiple_events_sequential(self, audit_logger: AuditLogger) -> None:
        """Log multiple events sequentially."""
        events = [
            AuditEvent(
                event_type=AuditEventType.BINARY_LOADED,
                severity=AuditSeverity.INFO,
                description=f"Binary {i} loaded",
            )
            for i in range(5)
        ]

        for event in events:
            audit_logger.log_event(event)

        log_files = list(audit_logger.log_dir.glob("audit_*.log"))
        assert log_files

        with open(log_files[0]) as f:
            content = f.read()
            for i in range(5):
                assert f"Binary {i} loaded" in content

    def test_hash_chain_integrity(self, audit_logger: AuditLogger) -> None:
        """Hash chain links events for tamper detection."""
        event1 = AuditEvent(
            event_type=AuditEventType.SYSTEM_START,
            severity=AuditSeverity.INFO,
            description="System started",
        )

        event2 = AuditEvent(
            event_type=AuditEventType.BINARY_LOADED,
            severity=AuditSeverity.INFO,
            description="Binary loaded",
        )

        audit_logger.log_event(event1)
        audit_logger.log_event(event2)

        hash_chain_file = audit_logger.log_dir / ".hash_chain"
        assert hash_chain_file.exists()

        last_hash = hash_chain_file.read_text().strip()
        assert len(last_hash) == 64

    def test_verify_log_integrity_detects_tampering(self, audit_logger: AuditLogger) -> None:
        """Verify log integrity detects tampering."""
        event = AuditEvent(
            event_type=AuditEventType.EXPLOIT_ATTEMPT,
            severity=AuditSeverity.HIGH,
            description="Original event",
        )

        audit_logger.log_event(event)

        log_files = list(audit_logger.log_dir.glob("audit_*.log"))
        log_file = log_files[0]

        original_content = Path(log_file).read_text()
        tampered_content = original_content.replace("Original event", "Tampered event")

        with open(log_file, "w") as f:
            f.write(tampered_content)

        is_valid = audit_logger.verify_log_integrity(log_file)

        assert not is_valid

    def test_verify_log_integrity_validates_untampered(self, audit_logger: AuditLogger) -> None:
        """Verify log integrity passes for untampered logs."""
        event = AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.INFO,
            description="Tool executed",
        )

        audit_logger.log_event(event)

        log_files = list(audit_logger.log_dir.glob("audit_*.log"))
        log_file = log_files[0]

        is_valid = audit_logger.verify_log_integrity(log_file)

        assert is_valid

    def test_log_rotation_on_size_limit(self, audit_logger: AuditLogger) -> None:
        """Log rotation occurs when size limit is exceeded."""
        large_details = {"data": "X" * 500}

        for i in range(10):
            event = AuditEvent(
                event_type=AuditEventType.BINARY_LOADED,
                severity=AuditSeverity.INFO,
                description=f"Large event {i}",
                details=large_details,
            )
            audit_logger.log_event(event)

        log_files = list(audit_logger.log_dir.glob("audit_*.log*"))
        assert len(log_files) > 1

    def test_search_events_by_type(self, audit_logger: AuditLogger) -> None:
        """Search events by event type."""
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.EXPLOIT_ATTEMPT,
                severity=AuditSeverity.HIGH,
                description="Exploit 1",
            )
        )

        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.BINARY_LOADED,
                severity=AuditSeverity.INFO,
                description="Binary 1",
            )
        )

        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.EXPLOIT_ATTEMPT,
                severity=AuditSeverity.HIGH,
                description="Exploit 2",
            )
        )

        results = audit_logger.search_events(event_type=AuditEventType.EXPLOIT_ATTEMPT)

        assert len(results) >= 2
        assert all(e["event_type"] == "exploit_attempt" for e in results)

    def test_search_events_by_severity(self, audit_logger: AuditLogger) -> None:
        """Search events by severity level."""
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.ERROR,
                severity=AuditSeverity.CRITICAL,
                description="Critical error",
            )
        )

        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.BINARY_LOADED,
                severity=AuditSeverity.INFO,
                description="Info event",
            )
        )

        results = audit_logger.search_events(severity=AuditSeverity.CRITICAL)

        assert len(results) >= 1
        assert all(e["severity"] == "critical" for e in results)

    def test_search_events_by_time_range(self, audit_logger: AuditLogger) -> None:
        """Search events within time range."""
        from datetime import UTC, datetime, timedelta

        start_time = datetime.now(UTC)

        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.SYSTEM_START,
                severity=AuditSeverity.INFO,
                description="Within range",
            )
        )

        end_time = datetime.now(UTC) + timedelta(seconds=1)

        results = audit_logger.search_events(
            start_time=start_time,
            end_time=end_time,
        )

        assert len(results) >= 1


class TestEncryptedLogging:
    """Test encrypted audit logging."""

    def test_encrypt_log_entry_produces_ciphertext(self, encrypted_audit_logger: AuditLogger) -> None:
        """Encrypted entries are not plaintext."""
        event = AuditEvent(
            event_type=AuditEventType.CREDENTIAL_ACCESS,
            severity=AuditSeverity.CRITICAL,
            description="Sensitive credential access",
            details={"password": "secret123"},
        )

        encrypted_audit_logger.log_event(event)

        log_files = list(encrypted_audit_logger.log_dir.glob("audit_*.log"))
        assert log_files

        with open(log_files[0], "rb") as f:
            content = f.read()

            assert b"secret123" not in content
            assert b"Sensitive credential access" not in content

    def test_decrypt_log_entry_recovers_plaintext(self, encrypted_audit_logger: AuditLogger) -> None:
        """Decrypted entries recover original data."""
        event = AuditEvent(
            event_type=AuditEventType.PRIVILEGE_ESCALATION,
            severity=AuditSeverity.CRITICAL,
            description="Privilege escalation detected",
            details={"user": "admin", "method": "token_manipulation"},
        )

        encrypted_audit_logger.log_event(event)

        log_files = list(encrypted_audit_logger.log_dir.glob("audit_*.log"))
        log_file = log_files[0]

        events = encrypted_audit_logger.read_log_file(log_file)

        assert len(events) > 0
        found = False
        for evt in events:
            if evt.get("description") == "Privilege escalation detected":
                assert evt["details"]["user"] == "admin"
                assert evt["details"]["method"] == "token_manipulation"
                found = True
                break

        assert found


class TestEventStatistics:
    """Test event statistics and reporting."""

    def test_get_event_statistics(self, audit_logger: AuditLogger) -> None:
        """Get statistics on logged events."""
        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.EXPLOIT_ATTEMPT,
                severity=AuditSeverity.HIGH,
                description="Attempt 1",
            )
        )

        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.EXPLOIT_ATTEMPT,
                severity=AuditSeverity.HIGH,
                description="Attempt 2",
            )
        )

        audit_logger.log_event(
            AuditEvent(
                event_type=AuditEventType.EXPLOIT_SUCCESS,
                severity=AuditSeverity.CRITICAL,
                description="Success",
            )
        )

        stats = audit_logger.get_statistics()

        assert "event_types" in stats
        assert stats["event_types"]["exploit_attempt"] >= 2
        assert stats["event_types"]["exploit_success"] >= 1
        assert "severities" in stats
        assert stats["severities"]["high"] >= 2
        assert stats["severities"]["critical"] >= 1


class TestThreadSafety:
    """Test concurrent logging operations."""

    def test_concurrent_logging_thread_safe(self, audit_logger: AuditLogger) -> None:
        """Concurrent logging from multiple threads is safe."""
        import threading

        def log_events(logger: AuditLogger, thread_id: int) -> None:
            for i in range(10):
                event = AuditEvent(
                    event_type=AuditEventType.BINARY_LOADED,
                    severity=AuditSeverity.INFO,
                    description=f"Thread {thread_id} event {i}",
                )
                logger.log_event(event)

        threads = [
            threading.Thread(target=log_events, args=(audit_logger, i))
            for i in range(5)
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        log_files = list(audit_logger.log_dir.glob("audit_*.log*"))
        total_events = 0

        for log_file in log_files:
            events = audit_logger.read_log_file(log_file)
            total_events += len(events)

        assert total_events >= 50


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_log_event_with_empty_details(self, audit_logger: AuditLogger) -> None:
        """Log event with empty details dictionary."""
        event = AuditEvent(
            event_type=AuditEventType.SYSTEM_START,
            severity=AuditSeverity.INFO,
            description="Empty details",
            details={},
        )

        audit_logger.log_event(event)

        log_files = list(audit_logger.log_dir.glob("audit_*.log"))
        assert log_files

    def test_log_event_with_none_details(self, audit_logger: AuditLogger) -> None:
        """Log event with None details."""
        event = AuditEvent(
            event_type=AuditEventType.SYSTEM_START,
            severity=AuditSeverity.INFO,
            description="None details",
            details=None,
        )

        audit_logger.log_event(event)

        log_files = list(audit_logger.log_dir.glob("audit_*.log"))
        assert log_files

    def test_log_event_with_large_details(self, audit_logger: AuditLogger) -> None:
        """Log event with very large details object."""
        large_data = {f"key_{i}": f"value_{i}" * 100 for i in range(100)}

        event = AuditEvent(
            event_type=AuditEventType.BINARY_LOADED,
            severity=AuditSeverity.INFO,
            description="Large details",
            details=large_data,
        )

        audit_logger.log_event(event)

        log_files = list(audit_logger.log_dir.glob("audit_*.log*"))
        assert log_files

    def test_read_corrupted_log_file_handles_gracefully(self, audit_logger: AuditLogger, temp_log_dir: Path) -> None:
        """Reading corrupted log file handles errors gracefully."""
        corrupted_log = temp_log_dir / "audit_corrupted.log"
        corrupted_log.write_text("This is not valid JSON\n{invalid json}")

        events = audit_logger.read_log_file(corrupted_log)

        assert isinstance(events, list)

    def test_verify_integrity_nonexistent_file(self, audit_logger: AuditLogger, temp_log_dir: Path) -> None:
        """Verify integrity of non-existent file returns False."""
        nonexistent = temp_log_dir / "does_not_exist.log"

        is_valid = audit_logger.verify_log_integrity(nonexistent)

        assert not is_valid
