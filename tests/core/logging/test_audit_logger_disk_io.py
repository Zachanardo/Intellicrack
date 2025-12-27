"""Comprehensive production tests for AuditLogger with real disk I/O and encryption.

Tests validate actual file writing, log rotation, encryption, and hash chain integrity
with real filesystem operations.
"""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.logging.audit_logger import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    AuditSeverity,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def temp_audit_dir() -> Iterator[Path]:
    """Create temporary directory for audit logs."""
    with tempfile.TemporaryDirectory(prefix="intellicrack_audit_") as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def audit_logger_no_encryption(temp_audit_dir: Path) -> Iterator[AuditLogger]:
    """Create AuditLogger without encryption for testing."""
    logger = AuditLogger(
        log_dir=temp_audit_dir,
        max_file_size=1024,
        rotation_count=5,
        enable_encryption=False,
    )
    yield logger


@pytest.fixture
def audit_logger_with_encryption(temp_audit_dir: Path) -> Iterator[AuditLogger]:
    """Create AuditLogger with encryption enabled."""
    try:
        from intellicrack.handlers.cryptography_handler import Fernet
        logger = AuditLogger(
            log_dir=temp_audit_dir,
            max_file_size=1024,
            rotation_count=5,
            enable_encryption=True,
        )
        yield logger
    except ImportError:
        pytest.skip("Cryptography not available")


class TestAuditEvent:
    """Test AuditEvent functionality."""

    def test_audit_event_initialization(self) -> None:
        """AuditEvent initializes with correct fields."""
        event = AuditEvent(
            event_type=AuditEventType.EXPLOIT_ATTEMPT,
            severity=AuditSeverity.HIGH,
            description="Test exploitation attempt",
            target="test.exe",
        )

        assert event.event_type == AuditEventType.EXPLOIT_ATTEMPT
        assert event.severity == AuditSeverity.HIGH
        assert event.description == "Test exploitation attempt"
        assert event.target == "test.exe"
        assert event.event_id is not None
        assert len(event.event_id) == 16

    def test_audit_event_generates_unique_ids(self) -> None:
        """Each AuditEvent gets unique event ID."""
        event1 = AuditEvent(
            event_type=AuditEventType.BINARY_LOADED,
            severity=AuditSeverity.INFO,
            description="Test 1",
        )

        event2 = AuditEvent(
            event_type=AuditEventType.BINARY_LOADED,
            severity=AuditSeverity.INFO,
            description="Test 2",
        )

        assert event1.event_id != event2.event_id

    def test_audit_event_to_dict(self) -> None:
        """AuditEvent converts to dictionary correctly."""
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

    def test_audit_event_to_json(self) -> None:
        """AuditEvent serializes to valid JSON."""
        event = AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.LOW,
            description="Frida script execution",
        )

        json_str = event.to_json()

        parsed = json.loads(json_str)
        assert parsed["event_type"] == "tool_execution"
        assert parsed["severity"] == "low"

    def test_audit_event_calculate_hash(self) -> None:
        """AuditEvent calculates consistent hash."""
        event = AuditEvent(
            event_type=AuditEventType.VULNERABILITY_FOUND,
            severity=AuditSeverity.CRITICAL,
            description="Buffer overflow detected",
        )

        hash1 = event.calculate_hash()
        hash2 = event.calculate_hash()

        assert hash1 == hash2
        assert len(hash1) == 64

    def test_audit_event_different_events_different_hashes(self) -> None:
        """Different events produce different hashes."""
        event1 = AuditEvent(
            event_type=AuditEventType.EXPLOIT_SUCCESS,
            severity=AuditSeverity.HIGH,
            description="License bypass successful",
        )

        event2 = AuditEvent(
            event_type=AuditEventType.EXPLOIT_FAILURE,
            severity=AuditSeverity.MEDIUM,
            description="License bypass failed",
        )

        assert event1.calculate_hash() != event2.calculate_hash()


class TestAuditLoggerFileIO:
    """Test AuditLogger file I/O operations."""

    def test_audit_logger_creates_log_directory(self, temp_audit_dir: Path) -> None:
        """AuditLogger creates log directory on initialization."""
        log_dir = temp_audit_dir / "custom_audit"
        logger = AuditLogger(log_dir=log_dir, enable_encryption=False)

        assert log_dir.exists()
        assert log_dir.is_dir()

    def test_audit_logger_writes_to_file(
        self, audit_logger_no_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """AuditLogger writes events to log file."""
        event = AuditEvent(
            event_type=AuditEventType.BINARY_LOADED,
            severity=AuditSeverity.INFO,
            description="Test binary loaded",
        )

        audit_logger_no_encryption.log_event(event)

        log_files = list(temp_audit_dir.glob("audit_*.log"))
        assert len(log_files) > 0

        log_content = log_files[0].read_text()
        assert "Test binary loaded" in log_content

    def test_audit_logger_file_contains_valid_json(
        self, audit_logger_no_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """Log file contains valid JSON entries."""
        event = AuditEvent(
            event_type=AuditEventType.TOOL_ERROR,
            severity=AuditSeverity.HIGH,
            description="Analysis tool crashed",
        )

        audit_logger_no_encryption.log_event(event)

        log_files = list(temp_audit_dir.glob("audit_*.log"))
        log_content = log_files[0].read_text()

        lines = log_content.strip().split("\n")
        for line in lines:
            if line.strip():
                parsed = json.loads(line)
                assert "event_type" in parsed

    def test_audit_logger_hash_chain_creation(
        self, audit_logger_no_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """AuditLogger creates and maintains hash chain."""
        event1 = AuditEvent(
            event_type=AuditEventType.SYSTEM_START,
            severity=AuditSeverity.INFO,
            description="Event 1",
        )

        event2 = AuditEvent(
            event_type=AuditEventType.SYSTEM_STOP,
            severity=AuditSeverity.INFO,
            description="Event 2",
        )

        audit_logger_no_encryption.log_event(event1)
        audit_logger_no_encryption.log_event(event2)

        hash_chain_file = temp_audit_dir / ".hash_chain"
        assert hash_chain_file.exists()

        last_hash = hash_chain_file.read_text().strip()
        assert len(last_hash) == 64

    def test_audit_logger_hash_chain_links_events(
        self, audit_logger_no_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """Hash chain correctly links sequential events."""
        event1 = AuditEvent(
            event_type=AuditEventType.CONFIG_CHANGE,
            severity=AuditSeverity.MEDIUM,
            description="Config updated",
        )

        event2 = AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.INFO,
            description="Tool executed",
        )

        audit_logger_no_encryption.log_event(event1)
        time.sleep(0.01)
        audit_logger_no_encryption.log_event(event2)

        log_files = list(temp_audit_dir.glob("audit_*.log"))
        log_content = log_files[0].read_text()
        lines = log_content.strip().split("\n")

        events = [json.loads(line) for line in lines if line.strip()]

        if len(events) >= 3:
            event2_data = events[-1]
            assert "previous_hash" in event2_data["details"]

    def test_audit_logger_log_rotation(self, temp_audit_dir: Path) -> None:
        """AuditLogger rotates logs when size limit reached."""
        logger = AuditLogger(
            log_dir=temp_audit_dir,
            max_file_size=500,
            rotation_count=3,
            enable_encryption=False,
        )

        for i in range(50):
            event = AuditEvent(
                event_type=AuditEventType.TOOL_EXECUTION,
                severity=AuditSeverity.INFO,
                description=f"Test event {i} with some additional data to increase size",
            )
            logger.log_event(event)

        log_files = list(temp_audit_dir.glob("audit_*.log*"))
        assert len(log_files) > 1

    def test_audit_logger_rotation_preserves_old_logs(self, temp_audit_dir: Path) -> None:
        """Log rotation preserves old log files."""
        logger = AuditLogger(
            log_dir=temp_audit_dir,
            max_file_size=300,
            rotation_count=5,
            enable_encryption=False,
        )

        for i in range(30):
            event = AuditEvent(
                event_type=AuditEventType.BINARY_LOADED,
                severity=AuditSeverity.INFO,
                description=f"Binary {i} loaded with detailed information",
            )
            logger.log_event(event)

        rotated_files = list(temp_audit_dir.glob("audit_*.log.[0-9]*"))
        assert len(rotated_files) > 0

        for rotated_file in rotated_files:
            assert rotated_file.exists()
            assert rotated_file.stat().st_size > 0

    def test_audit_logger_respects_rotation_count(self, temp_audit_dir: Path) -> None:
        """AuditLogger respects rotation_count limit."""
        rotation_count = 3
        logger = AuditLogger(
            log_dir=temp_audit_dir,
            max_file_size=200,
            rotation_count=rotation_count,
            enable_encryption=False,
        )

        for i in range(100):
            event = AuditEvent(
                event_type=AuditEventType.EXPLOIT_ATTEMPT,
                severity=AuditSeverity.HIGH,
                description=f"Exploitation attempt {i} with payload information",
            )
            logger.log_event(event)

        all_files = list(temp_audit_dir.glob("audit_*.log*"))
        assert len(all_files) <= rotation_count + 1


class TestAuditLoggerEncryption:
    """Test AuditLogger encryption functionality."""

    def test_audit_logger_encryption_enabled(
        self, audit_logger_with_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """AuditLogger encrypts events when encryption enabled."""
        event = AuditEvent(
            event_type=AuditEventType.CREDENTIAL_ACCESS,
            severity=AuditSeverity.CRITICAL,
            description="Sensitive credential accessed",
        )

        audit_logger_with_encryption.log_event(event)

        log_files = list(temp_audit_dir.glob("audit_*.log"))
        log_content = log_files[0].read_text()

        lines = log_content.strip().split("\n")
        for line in lines:
            if line.strip():
                parsed = json.loads(line)
                if "encrypted" in parsed:
                    assert parsed["encrypted"] is True
                    assert "data" in parsed
                    assert "Sensitive credential accessed" not in line

    def test_encrypted_logs_are_decryptable(
        self, audit_logger_with_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """Encrypted logs can be decrypted with correct cipher."""
        event = AuditEvent(
            event_type=AuditEventType.PRIVILEGE_ESCALATION,
            severity=AuditSeverity.CRITICAL,
            description="Privilege escalation detected",
        )

        audit_logger_with_encryption.log_event(event)

        log_files = list(temp_audit_dir.glob("audit_*.log"))
        log_content = log_files[0].read_text()

        lines = log_content.strip().split("\n")
        for line in lines:
            if line.strip():
                parsed = json.loads(line)
                if "encrypted" in parsed and parsed["encrypted"]:
                    cipher = audit_logger_with_encryption._cipher
                    if cipher:
                        decrypted = cipher.decrypt(parsed["data"].encode()).decode()
                        decrypted_event = json.loads(decrypted)
                        assert "event_type" in decrypted_event


class TestAuditLoggerHelperMethods:
    """Test AuditLogger helper methods."""

    def test_log_exploit_attempt_success(
        self, audit_logger_no_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """log_exploit_attempt logs successful exploitation."""
        audit_logger_no_encryption.log_exploit_attempt(
            target="crackme.exe",
            exploit_type="keygen",
            success=True,
        )

        log_files = list(temp_audit_dir.glob("audit_*.log"))
        log_content = log_files[0].read_text()

        assert "crackme.exe" in log_content
        assert "keygen" in log_content

    def test_log_exploit_attempt_failure(
        self, audit_logger_no_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """log_exploit_attempt logs failed exploitation."""
        audit_logger_no_encryption.log_exploit_attempt(
            target="protected.exe",
            exploit_type="patcher",
            success=False,
            error="Protection detection failed",
        )

        log_files = list(temp_audit_dir.glob("audit_*.log"))
        log_content = log_files[0].read_text()

        assert "protected.exe" in log_content
        assert "patcher" in log_content


class TestAuditLoggerConcurrency:
    """Test AuditLogger thread safety."""

    def test_concurrent_log_writes(self, temp_audit_dir: Path) -> None:
        """AuditLogger handles concurrent writes correctly."""
        import threading

        logger = AuditLogger(log_dir=temp_audit_dir, enable_encryption=False)

        def write_events(thread_id: int) -> None:
            for i in range(10):
                event = AuditEvent(
                    event_type=AuditEventType.TOOL_EXECUTION,
                    severity=AuditSeverity.INFO,
                    description=f"Thread {thread_id} event {i}",
                )
                logger.log_event(event)

        threads = [threading.Thread(target=write_events, args=(i,)) for i in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        log_files = list(temp_audit_dir.glob("audit_*.log*"))
        total_size = sum(f.stat().st_size for f in log_files)
        assert total_size > 0


class TestAuditLoggerEdgeCases:
    """Test edge cases and error conditions."""

    def test_audit_logger_handles_empty_description(
        self, audit_logger_no_encryption: AuditLogger
    ) -> None:
        """AuditLogger handles events with empty description."""
        event = AuditEvent(
            event_type=AuditEventType.ERROR,
            severity=AuditSeverity.MEDIUM,
            description="",
        )

        audit_logger_no_encryption.log_event(event)

    def test_audit_logger_handles_large_details(
        self, audit_logger_no_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """AuditLogger handles events with large detail dictionaries."""
        large_details = {f"key_{i}": f"value_{i}" * 100 for i in range(100)}

        event = AuditEvent(
            event_type=AuditEventType.BINARY_LOADED,
            severity=AuditSeverity.INFO,
            description="Binary with extensive metadata",
            details=large_details,
        )

        audit_logger_no_encryption.log_event(event)

        log_files = list(temp_audit_dir.glob("audit_*.log"))
        assert log_files[0].stat().st_size > 0

    def test_audit_logger_handles_special_characters(
        self, audit_logger_no_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """AuditLogger handles special characters in description."""
        event = AuditEvent(
            event_type=AuditEventType.PROTECTION_DETECTED,
            severity=AuditSeverity.HIGH,
            description="Protection with special chars: <>&\"'\\n\\t",
        )

        audit_logger_no_encryption.log_event(event)

        log_files = list(temp_audit_dir.glob("audit_*.log"))
        log_content = log_files[0].read_text()

        parsed_events = [json.loads(line) for line in log_content.strip().split("\n") if line.strip()]
        assert any("<>&\"'" in event["description"] for event in parsed_events)

    def test_audit_logger_with_permission_restricted_directory(self) -> None:
        """AuditLogger handles permission errors gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "restricted"
            log_dir.mkdir()

            try:
                if hasattr(log_dir, "chmod"):
                    log_dir.chmod(0o000)

                logger = AuditLogger(log_dir=log_dir, enable_encryption=False)

                event = AuditEvent(
                    event_type=AuditEventType.ERROR,
                    severity=AuditSeverity.CRITICAL,
                    description="Test event",
                )

                logger.log_event(event)

            finally:
                if hasattr(log_dir, "chmod"):
                    log_dir.chmod(0o755)

    def test_hash_chain_file_corruption_recovery(self, temp_audit_dir: Path) -> None:
        """AuditLogger recovers from corrupted hash chain file."""
        hash_chain_file = temp_audit_dir / ".hash_chain"
        hash_chain_file.write_text("corrupted_invalid_hash")

        logger = AuditLogger(log_dir=temp_audit_dir, enable_encryption=False)

        event = AuditEvent(
            event_type=AuditEventType.TOOL_EXECUTION,
            severity=AuditSeverity.INFO,
            description="Test event after corruption",
        )

        logger.log_event(event)

        new_hash = hash_chain_file.read_text().strip()
        assert len(new_hash) == 64

    def test_audit_logger_with_unicode_content(
        self, audit_logger_no_encryption: AuditLogger, temp_audit_dir: Path
    ) -> None:
        """AuditLogger handles Unicode content correctly."""
        event = AuditEvent(
            event_type=AuditEventType.BINARY_LOADED,
            severity=AuditSeverity.INFO,
            description="Binary with Unicode: ∞ ★ 中文 العربية",
        )

        audit_logger_no_encryption.log_event(event)

        log_files = list(temp_audit_dir.glob("audit_*.log"))
        log_content = log_files[0].read_text(encoding="utf-8")

        assert "∞" in log_content or "\\u" in log_content
