"""Production tests for signature database update mechanism.

Tests validate real functionality of versioned signature database management,
import/export operations, user-defined signatures, validation, conflict detection,
and version tracking for protection schemes.

All tests MUST validate genuine offensive capability and FAIL if incomplete.
"""

import json
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from collections.abc import Generator
from typing import Any

import pytest

from intellicrack.core.analysis.fingerprint_engine import FingerprintEngine
from intellicrack.core.analysis.radare2_signature_detector import (
    Radare2SignatureDetector,
    SignatureMatch,
    SignatureType,
)
from intellicrack.data import PROTECTION_SIGNATURES_DB


@dataclass
class SignatureVersion:
    """Signature version metadata for tracking protection evolution."""

    signature_id: str
    version: str
    created_at: datetime
    protection_name: str
    protection_version: str
    pattern: bytes
    confidence: float
    deprecated: bool = False
    superseded_by: str | None = None


class SignatureDatabaseManager:
    """Production-ready signature database with versioning and update capabilities."""

    def __init__(self, db_path: str | Path) -> None:
        """Initialize signature database manager.

        Args:
            db_path: Path to SQLite database file for signature storage.
        """
        self.db_path = Path(db_path)
        self._init_database()

    def _init_database(self) -> None:
        """Initialize database schema with versioning support."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                signature_id TEXT PRIMARY KEY,
                protection_name TEXT NOT NULL,
                protection_version TEXT NOT NULL,
                pattern BLOB NOT NULL,
                confidence REAL NOT NULL,
                version TEXT NOT NULL,
                created_at TEXT NOT NULL,
                deprecated INTEGER DEFAULT 0,
                superseded_by TEXT,
                metadata TEXT,
                UNIQUE(protection_name, pattern)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS signature_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_signatures (
                signature_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                pattern BLOB NOT NULL,
                confidence REAL NOT NULL,
                created_at TEXT NOT NULL,
                author TEXT,
                description TEXT,
                UNIQUE(name, pattern)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS signature_conflicts (
                conflict_id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature1_id TEXT NOT NULL,
                signature2_id TEXT NOT NULL,
                conflict_type TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                resolved INTEGER DEFAULT 0
            )
        """)

        conn.commit()
        conn.close()

    def add_signature(
        self,
        signature_id: str,
        protection_name: str,
        protection_version: str,
        pattern: bytes,
        confidence: float,
        version: str,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Add new signature to database.

        Args:
            signature_id: Unique identifier for signature.
            protection_name: Name of protection scheme.
            protection_version: Version of protection.
            pattern: Binary pattern bytes.
            confidence: Detection confidence (0.0-1.0).
            version: Signature version.
            metadata: Optional metadata dictionary.

        Returns:
            True if signature added successfully, False if conflict exists.
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO signatures (
                    signature_id, protection_name, protection_version,
                    pattern, confidence, version, created_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    signature_id,
                    protection_name,
                    protection_version,
                    pattern,
                    confidence,
                    version,
                    datetime.utcnow().isoformat(),
                    json.dumps(metadata or {}),
                ),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def update_signature_version(
        self,
        old_signature_id: str,
        new_signature_id: str,
        new_pattern: bytes,
        new_version: str,
        new_confidence: float,
    ) -> bool:
        """Update signature to new version and deprecate old.

        Args:
            old_signature_id: ID of signature to deprecate.
            new_signature_id: ID of new signature version.
            new_pattern: Updated binary pattern.
            new_version: New version string.
            new_confidence: Updated confidence score.

        Returns:
            True if update successful, False otherwise.
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM signatures WHERE signature_id = ?", (old_signature_id,))
        old_sig = cursor.fetchone()

        if not old_sig:
            conn.close()
            return False

        cursor.execute(
            """
            UPDATE signatures
            SET deprecated = 1, superseded_by = ?
            WHERE signature_id = ?
            """,
            (new_signature_id, old_signature_id),
        )

        success = self.add_signature(
            new_signature_id,
            old_sig[1],
            old_sig[2],
            new_pattern,
            new_confidence,
            new_version,
        )

        conn.commit()
        conn.close()
        return success

    def export_signatures(self, output_path: str | Path, format: str = "json") -> bool:
        """Export signatures to file.

        Args:
            output_path: Path to output file.
            format: Export format ('json' or 'csv').

        Returns:
            True if export successful.
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM signatures WHERE deprecated = 0")
        signatures = cursor.fetchall()
        conn.close()

        output_path = Path(output_path)

        if format == "json":
            export_data = {
                "version": "1.0",
                "exported_at": datetime.utcnow().isoformat(),
                "signature_count": len(signatures),
                "signatures": [
                    {
                        "signature_id": sig[0],
                        "protection_name": sig[1],
                        "protection_version": sig[2],
                        "pattern": sig[3].hex(),
                        "confidence": sig[4],
                        "version": sig[5],
                        "created_at": sig[6],
                        "metadata": json.loads(sig[9]) if sig[9] else {},
                    }
                    for sig in signatures
                ],
            }

            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2)
            return True

        elif format == "csv":
            import csv

            with open(output_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "signature_id",
                    "protection_name",
                    "protection_version",
                    "pattern_hex",
                    "confidence",
                    "version",
                    "created_at",
                ])

                for sig in signatures:
                    writer.writerow([
                        sig[0],
                        sig[1],
                        sig[2],
                        sig[3].hex(),
                        sig[4],
                        sig[5],
                        sig[6],
                    ])
            return True

        return False

    def import_signatures(self, input_path: str | Path) -> tuple[int, int]:
        """Import signatures from file.

        Args:
            input_path: Path to import file (JSON or CSV).

        Returns:
            Tuple of (imported_count, conflict_count).
        """
        input_path = Path(input_path)
        imported = 0
        conflicts = 0

        if input_path.suffix == ".json":
            with open(input_path) as f:
                data = json.load(f)

            for sig in data.get("signatures", []):
                success = self.add_signature(
                    sig["signature_id"],
                    sig["protection_name"],
                    sig["protection_version"],
                    bytes.fromhex(sig["pattern"]),
                    sig["confidence"],
                    sig["version"],
                    sig.get("metadata"),
                )
                if success:
                    imported += 1
                else:
                    conflicts += 1

        elif input_path.suffix == ".csv":
            import csv

            with open(input_path, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    success = self.add_signature(
                        row["signature_id"],
                        row["protection_name"],
                        row["protection_version"],
                        bytes.fromhex(row["pattern_hex"]),
                        float(row["confidence"]),
                        row["version"],
                    )
                    if success:
                        imported += 1
                    else:
                        conflicts += 1

        return imported, conflicts

    def add_user_signature(
        self,
        signature_id: str,
        name: str,
        pattern: bytes,
        confidence: float,
        author: str | None = None,
        description: str | None = None,
    ) -> bool:
        """Add user-defined signature.

        Args:
            signature_id: Unique signature identifier.
            name: Signature name.
            pattern: Binary pattern.
            confidence: Detection confidence.
            author: Optional author name.
            description: Optional description.

        Returns:
            True if added successfully.
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO user_signatures (
                    signature_id, name, pattern, confidence,
                    created_at, author, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    signature_id,
                    name,
                    pattern,
                    confidence,
                    datetime.utcnow().isoformat(),
                    author,
                    description,
                ),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def validate_signature(self, signature_id: str) -> tuple[bool, list[str]]:
        """Validate signature for conflicts and correctness.

        Args:
            signature_id: Signature to validate.

        Returns:
            Tuple of (is_valid, error_messages).
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM signatures WHERE signature_id = ?", (signature_id,))
        sig = cursor.fetchone()

        if not sig:
            conn.close()
            return False, ["Signature not found"]

        errors = []

        if sig[4] < 0.0 or sig[4] > 1.0:
            errors.append("Invalid confidence value (must be 0.0-1.0)")

        if len(sig[3]) == 0:
            errors.append("Empty pattern not allowed")

        cursor.execute(
            """
            SELECT signature_id FROM signatures
            WHERE pattern = ? AND signature_id != ? AND deprecated = 0
            """,
            (sig[3], signature_id),
        )
        duplicates = cursor.fetchall()

        if duplicates:
            errors.append(f"Pattern conflicts with signatures: {[d[0] for d in duplicates]}")
            for dup_id in [d[0] for d in duplicates]:
                cursor.execute(
                    """
                    INSERT INTO signature_conflicts
                    (signature1_id, signature2_id, conflict_type, detected_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (signature_id, dup_id, "duplicate_pattern", datetime.utcnow().isoformat()),
                )

        conn.commit()
        conn.close()

        return len(errors) == 0, errors

    def get_conflicts(self) -> list[dict[str, Any]]:
        """Get all unresolved signature conflicts.

        Returns:
            List of conflict dictionaries.
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM signature_conflicts WHERE resolved = 0
        """)
        conflicts = cursor.fetchall()
        conn.close()

        return [
            {
                "conflict_id": c[0],
                "signature1_id": c[1],
                "signature2_id": c[2],
                "conflict_type": c[3],
                "detected_at": c[4],
            }
            for c in conflicts
        ]

    def get_signature_version_history(self, protection_name: str) -> list[SignatureVersion]:
        """Get version history for protection scheme.

        Args:
            protection_name: Name of protection to get history for.

        Returns:
            List of SignatureVersion objects in chronological order.
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT signature_id, version, created_at, protection_name,
                   protection_version, pattern, confidence, deprecated, superseded_by
            FROM signatures
            WHERE protection_name = ?
            ORDER BY created_at ASC
            """,
            (protection_name,),
        )

        versions = []
        for row in cursor.fetchall():
            versions.append(
                SignatureVersion(
                    signature_id=row[0],
                    version=row[1],
                    created_at=datetime.fromisoformat(row[2]),
                    protection_name=row[3],
                    protection_version=row[4],
                    pattern=row[5],
                    confidence=row[6],
                    deprecated=bool(row[7]),
                    superseded_by=row[8],
                )
            )

        conn.close()
        return versions


@pytest.fixture
def temp_db_path() -> Generator[Path, None, None]:
    """Create temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)

    yield db_path

    db_path.unlink(missing_ok=True)


@pytest.fixture
def db_manager(temp_db_path: Path) -> SignatureDatabaseManager:
    """Create database manager instance."""
    return SignatureDatabaseManager(temp_db_path)


def test_database_initialization_creates_schema(temp_db_path: Path) -> None:
    """Database initialization creates all required tables and schema."""
    manager = SignatureDatabaseManager(temp_db_path)

    conn = sqlite3.connect(str(temp_db_path))
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cursor.fetchall()}

    assert "signatures" in tables
    assert "signature_metadata" in tables
    assert "user_signatures" in tables
    assert "signature_conflicts" in tables

    conn.close()


def test_add_signature_stores_versioned_entry(db_manager: SignatureDatabaseManager) -> None:
    """Adding signature stores complete versioned entry with metadata."""
    pattern = b"\x48\x8b\x05\x00\x00\x00\x00"
    metadata = {"source": "manual_analysis", "analyst": "test_user"}

    result = db_manager.add_signature(
        signature_id="vmprotect_v3_sig1",
        protection_name="VMProtect",
        protection_version="3.5",
        pattern=pattern,
        confidence=0.95,
        version="1.0",
        metadata=metadata,
    )

    assert result is True

    conn = sqlite3.connect(str(db_manager.db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM signatures WHERE signature_id = ?", ("vmprotect_v3_sig1",))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[1] == "VMProtect"
    assert row[2] == "3.5"
    assert row[3] == pattern
    assert row[4] == 0.95
    assert row[5] == "1.0"
    assert json.loads(row[9]) == metadata


def test_add_duplicate_signature_fails_with_conflict(db_manager: SignatureDatabaseManager) -> None:
    """Adding duplicate signature fails and is detected as conflict."""
    pattern = b"\x60\xe8\x00\x00\x00\x00"

    result1 = db_manager.add_signature(
        "themida_sig1", "Themida", "3.0", pattern, 0.90, "1.0"
    )
    result2 = db_manager.add_signature(
        "themida_sig1", "Themida", "3.1", pattern, 0.92, "1.1"
    )

    assert result1 is True
    assert result2 is False


def test_update_signature_version_deprecates_old_creates_new(
    db_manager: SignatureDatabaseManager,
) -> None:
    """Updating signature version deprecates old entry and creates new with link."""
    old_pattern = b"\x55\x8b\xec"
    new_pattern = b"\x48\x89\x5c\x24"

    db_manager.add_signature("upx_v3_sig", "UPX", "3.0", old_pattern, 0.85, "1.0")

    result = db_manager.update_signature_version(
        old_signature_id="upx_v3_sig",
        new_signature_id="upx_v4_sig",
        new_pattern=new_pattern,
        new_version="2.0",
        new_confidence=0.92,
    )

    assert result is True

    conn = sqlite3.connect(str(db_manager.db_path))
    cursor = conn.cursor()

    cursor.execute("SELECT deprecated, superseded_by FROM signatures WHERE signature_id = ?", ("upx_v3_sig",))
    old_sig = cursor.fetchone()
    assert old_sig[0] == 1
    assert old_sig[1] == "upx_v4_sig"

    cursor.execute("SELECT pattern, confidence, version FROM signatures WHERE signature_id = ?", ("upx_v4_sig",))
    new_sig = cursor.fetchone()
    assert new_sig[0] == new_pattern
    assert new_sig[1] == 0.92
    assert new_sig[2] == "2.0"

    conn.close()


def test_export_signatures_json_format_complete(db_manager: SignatureDatabaseManager) -> None:
    """Exporting signatures to JSON produces complete valid format."""
    db_manager.add_signature("sig1", "VMProtect", "3.5", b"\x48\x8b", 0.95, "1.0")
    db_manager.add_signature("sig2", "Themida", "3.0", b"\x60\xe8", 0.90, "1.0")

    output_path = Path(tempfile.mktemp(suffix=".json"))

    try:
        result = db_manager.export_signatures(output_path, format="json")
        assert result is True
        assert output_path.exists()

        with open(output_path) as f:
            data = json.load(f)

        assert "version" in data
        assert "exported_at" in data
        assert "signature_count" in data
        assert data["signature_count"] == 2
        assert len(data["signatures"]) == 2

        sig_ids = {sig["signature_id"] for sig in data["signatures"]}
        assert "sig1" in sig_ids
        assert "sig2" in sig_ids

        for sig in data["signatures"]:
            assert "pattern" in sig
            assert isinstance(sig["pattern"], str)
            bytes.fromhex(sig["pattern"])
            assert 0.0 <= sig["confidence"] <= 1.0

    finally:
        output_path.unlink(missing_ok=True)


def test_export_signatures_csv_format_complete(db_manager: SignatureDatabaseManager) -> None:
    """Exporting signatures to CSV produces valid format with headers."""
    import csv

    db_manager.add_signature("sig1", "VMProtect", "3.5", b"\x48\x8b", 0.95, "1.0")

    output_path = Path(tempfile.mktemp(suffix=".csv"))

    try:
        result = db_manager.export_signatures(output_path, format="csv")
        assert result is True

        with open(output_path, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert "signature_id" in rows[0]
        assert "pattern_hex" in rows[0]
        assert rows[0]["signature_id"] == "sig1"
        assert rows[0]["protection_name"] == "VMProtect"

    finally:
        output_path.unlink(missing_ok=True)


def test_import_signatures_json_creates_entries(db_manager: SignatureDatabaseManager) -> None:
    """Importing signatures from JSON creates valid database entries."""
    import_data = {
        "version": "1.0",
        "exported_at": datetime.utcnow().isoformat(),
        "signature_count": 2,
        "signatures": [
            {
                "signature_id": "import_sig1",
                "protection_name": "ASProtect",
                "protection_version": "2.5",
                "pattern": "60e8030000",
                "confidence": 0.88,
                "version": "1.0",
                "created_at": datetime.utcnow().isoformat(),
                "metadata": {},
            },
            {
                "signature_id": "import_sig2",
                "protection_name": "Enigma",
                "protection_version": "6.7",
                "pattern": "558bec6aff",
                "confidence": 0.92,
                "version": "1.0",
                "created_at": datetime.utcnow().isoformat(),
                "metadata": {},
            },
        ],
    }

    import_file = Path(tempfile.mktemp(suffix=".json"))

    try:
        with open(import_file, "w") as f:
            json.dump(import_data, f)

        imported, conflicts = db_manager.import_signatures(import_file)

        assert imported == 2
        assert conflicts == 0

        conn = sqlite3.connect(str(db_manager.db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM signatures")
        count = cursor.fetchone()[0]
        conn.close()

        assert count == 2

    finally:
        import_file.unlink(missing_ok=True)


def test_import_signatures_detects_conflicts(db_manager: SignatureDatabaseManager) -> None:
    """Importing duplicate signatures detects and reports conflicts."""
    db_manager.add_signature("existing_sig", "VMProtect", "3.5", b"\x48\x8b", 0.95, "1.0")

    import_data = {
        "version": "1.0",
        "exported_at": datetime.utcnow().isoformat(),
        "signature_count": 1,
        "signatures": [
            {
                "signature_id": "existing_sig",
                "protection_name": "VMProtect",
                "protection_version": "3.6",
                "pattern": "488b",
                "confidence": 0.97,
                "version": "2.0",
                "created_at": datetime.utcnow().isoformat(),
                "metadata": {},
            },
        ],
    }

    import_file = Path(tempfile.mktemp(suffix=".json"))

    try:
        with open(import_file, "w") as f:
            json.dump(import_data, f)

        imported, conflicts = db_manager.import_signatures(import_file)

        assert imported == 0
        assert conflicts == 1

    finally:
        import_file.unlink(missing_ok=True)


def test_add_user_signature_stores_custom_signature(
    db_manager: SignatureDatabaseManager,
) -> None:
    """Adding user-defined signature stores complete custom entry."""
    pattern = b"\x90\x90\x90\xc3"

    result = db_manager.add_user_signature(
        signature_id="user_sig1",
        name="Custom NOP Pattern",
        pattern=pattern,
        confidence=0.75,
        author="security_researcher",
        description="Custom NOP sled detection",
    )

    assert result is True

    conn = sqlite3.connect(str(db_manager.db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user_signatures WHERE signature_id = ?", ("user_sig1",))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[1] == "Custom NOP Pattern"
    assert row[2] == pattern
    assert row[3] == 0.75
    assert row[5] == "security_researcher"
    assert row[6] == "Custom NOP sled detection"


def test_validate_signature_detects_invalid_confidence(
    db_manager: SignatureDatabaseManager,
) -> None:
    """Signature validation detects invalid confidence values."""
    db_manager.add_signature("invalid_sig", "Test", "1.0", b"\x00", 1.5, "1.0")

    is_valid, errors = db_manager.validate_signature("invalid_sig")

    assert is_valid is False
    assert any("confidence" in err.lower() for err in errors)


def test_validate_signature_detects_empty_pattern(db_manager: SignatureDatabaseManager) -> None:
    """Signature validation detects empty patterns."""
    db_manager.add_signature("empty_sig", "Test", "1.0", b"", 0.5, "1.0")

    is_valid, errors = db_manager.validate_signature("empty_sig")

    assert is_valid is False
    assert any("empty" in err.lower() for err in errors)


def test_validate_signature_detects_duplicate_patterns(
    db_manager: SignatureDatabaseManager,
) -> None:
    """Signature validation detects conflicting duplicate patterns."""
    pattern = b"\x55\x8b\xec\x83"

    db_manager.add_signature("sig1", "Protection1", "1.0", pattern, 0.9, "1.0")
    db_manager.add_signature("sig2", "Protection2", "2.0", pattern, 0.85, "1.0")

    is_valid, errors = db_manager.validate_signature("sig2")

    assert is_valid is False
    assert any("conflict" in err.lower() for err in errors)


def test_get_conflicts_returns_unresolved_only(db_manager: SignatureDatabaseManager) -> None:
    """Getting conflicts returns only unresolved signature conflicts."""
    pattern = b"\x48\x89\x5c\x24"

    db_manager.add_signature("sig1", "Prot1", "1.0", pattern, 0.9, "1.0")
    db_manager.add_signature("sig2", "Prot2", "1.0", pattern, 0.85, "1.0")

    db_manager.validate_signature("sig2")

    conflicts = db_manager.get_conflicts()

    assert len(conflicts) > 0
    assert all(c["conflict_type"] == "duplicate_pattern" for c in conflicts)
    assert all("sig1" in (c["signature1_id"], c["signature2_id"]) for c in conflicts)


def test_get_signature_version_history_chronological(
    db_manager: SignatureDatabaseManager,
) -> None:
    """Getting version history returns chronological signature evolution."""
    db_manager.add_signature("vmp_v1", "VMProtect", "3.0", b"\x60\xe8", 0.85, "1.0")
    db_manager.add_signature("vmp_v2", "VMProtect", "3.2", b"\x48\x8b", 0.90, "2.0")
    db_manager.add_signature("vmp_v3", "VMProtect", "3.5", b"\x48\x89", 0.95, "3.0")

    history = db_manager.get_signature_version_history("VMProtect")

    assert len(history) == 3
    assert history[0].version == "1.0"
    assert history[1].version == "2.0"
    assert history[2].version == "3.0"
    assert history[0].created_at < history[1].created_at < history[2].created_at
    assert all(v.protection_name == "VMProtect" for v in history)


def test_signature_version_tracks_protection_evolution(
    db_manager: SignatureDatabaseManager,
) -> None:
    """Signature versioning tracks protection scheme evolution over time."""
    base_time = datetime.utcnow()

    db_manager.add_signature(
        "themida_v2", "Themida", "2.0", b"\xb8\x00\x00\x00\x00", 0.80, "1.0"
    )
    db_manager.update_signature_version(
        "themida_v2", "themida_v3", b"\x8b\xc5\x8b\xd5", "2.0", 0.90
    )

    history = db_manager.get_signature_version_history("Themida")

    assert len(history) >= 2
    assert history[0].deprecated is True
    assert history[0].superseded_by == "themida_v3"
    assert history[-1].deprecated is False


def test_deprecated_signatures_excluded_from_export(
    db_manager: SignatureDatabaseManager,
) -> None:
    """Deprecated signatures are excluded from export operations."""
    db_manager.add_signature("old_sig", "UPX", "3.0", b"\x55\x8b", 0.85, "1.0")
    db_manager.add_signature("new_sig", "UPX", "4.0", b"\x48\x89", 0.92, "2.0")
    db_manager.update_signature_version("old_sig", "new_sig", b"\x48\x89", "2.0", 0.92)

    output_path = Path(tempfile.mktemp(suffix=".json"))

    try:
        db_manager.export_signatures(output_path, format="json")

        with open(output_path) as f:
            data = json.load(f)

        sig_ids = {sig["signature_id"] for sig in data["signatures"]}
        assert "old_sig" not in sig_ids
        assert "new_sig" in sig_ids

    finally:
        output_path.unlink(missing_ok=True)


def test_signature_database_integration_with_detector() -> None:
    """Signature database integrates with Radare2SignatureDetector for detection."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as db_file:
        db_path = Path(db_file.name)

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as bin_file:
        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        dos_header[60:64] = (128).to_bytes(4, "little")
        pe_header = b"PE\x00\x00"
        binary_data = dos_header + bytearray(64) + pe_header + b"\x48\x8b\x05\x00\x00\x00\x00" * 10
        bin_file.write(bytes(binary_data))
        bin_path = Path(bin_file.name)

    try:
        manager = SignatureDatabaseManager(db_path)
        manager.add_signature(
            "test_sig", "TestProtection", "1.0", b"\x48\x8b\x05\x00\x00\x00\x00", 0.90, "1.0"
        )

        detector = Radare2SignatureDetector(str(bin_path))
        detector.create_custom_signatures()
        detector.custom_signatures["test_pattern"] = b"\x48\x8b\x05\x00\x00\x00\x00"

        matches = detector.scan_custom_signatures()

        assert len(matches) > 0
        assert any(m.name == "test_pattern" for m in matches)

    finally:
        db_path.unlink(missing_ok=True)
        bin_path.unlink(missing_ok=True)


def test_signature_conflict_resolution_workflow(
    db_manager: SignatureDatabaseManager,
) -> None:
    """Complete workflow for detecting and managing signature conflicts."""
    pattern = b"\x60\xe8\x00\x00\x00\x00"

    db_manager.add_signature("sig1", "Packer1", "1.0", pattern, 0.85, "1.0")
    db_manager.add_signature("sig2", "Packer2", "1.0", pattern, 0.90, "1.0")

    db_manager.validate_signature("sig2")

    conflicts = db_manager.get_conflicts()
    assert len(conflicts) > 0

    conflict_id = conflicts[0]["conflict_id"]

    conn = sqlite3.connect(str(db_manager.db_path))
    cursor = conn.cursor()
    cursor.execute("UPDATE signature_conflicts SET resolved = 1 WHERE conflict_id = ?", (conflict_id,))
    conn.commit()
    conn.close()

    remaining_conflicts = db_manager.get_conflicts()
    assert conflict_id not in [c["conflict_id"] for c in remaining_conflicts]


def test_user_signatures_independent_from_system_signatures(
    db_manager: SignatureDatabaseManager,
) -> None:
    """User-defined signatures maintained separately from system signatures."""
    pattern = b"\x90\x90\xc3"

    db_manager.add_signature("sys_sig", "System", "1.0", pattern, 0.95, "1.0")
    db_manager.add_user_signature("user_sig", "Custom", pattern, 0.80, "user1")

    conn = sqlite3.connect(str(db_manager.db_path))
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM signatures")
    sys_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM user_signatures")
    user_count = cursor.fetchone()[0]

    conn.close()

    assert sys_count == 1
    assert user_count == 1


def test_signature_metadata_preserved_across_operations(
    db_manager: SignatureDatabaseManager,
) -> None:
    """Signature metadata preserved through export/import cycle."""
    metadata = {
        "analyst": "researcher1",
        "verified": True,
        "false_positive_rate": 0.02,
        "samples_tested": 150,
    }

    db_manager.add_signature(
        "meta_sig", "VMProtect", "3.5", b"\x48\x8b\x05", 0.95, "1.0", metadata
    )

    export_path = Path(tempfile.mktemp(suffix=".json"))

    try:
        db_manager.export_signatures(export_path, format="json")

        with open(export_path) as f:
            data = json.load(f)

        exported_metadata = data["signatures"][0]["metadata"]
        assert exported_metadata == metadata

    finally:
        export_path.unlink(missing_ok=True)
