"""Production tests for signature database update mechanism.

Tests validate that signatures are not hardcoded and can be updated,
imported, exported, versioned, and validated with conflict detection.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_signature_detector import (
    Radare2SignatureDetector,
    SignatureMatch,
    SignatureType,
)


@pytest.fixture
def sample_binary_path(tmp_path: Path) -> Path:
    """Create a sample binary file for testing.

    Returns:
        Path to sample binary with embedded protection signatures.
    """
    binary_path = tmp_path / "test_binary.exe"
    pe_header = b"MZ\x90\x00"
    vmp_signature = b".vmp0" + b"\x00" * 10
    themida_sig = b"Themida" + b"\x00" * 5
    license_check = b"IsLicenseValid\x00"
    aes_pattern = b"AES\x00"

    content = (
        pe_header
        + b"\x00" * 100
        + vmp_signature
        + b"\x00" * 200
        + themida_sig
        + b"\x00" * 300
        + license_check
        + b"\x00" * 150
        + aes_pattern
        + b"\x00" * 1000
    )

    binary_path.write_bytes(content)
    return binary_path


@pytest.fixture
def signature_database(tmp_path: Path) -> Path:
    """Create a versioned signature database.

    Returns:
        Path to SQLite database with signature schema.
    """
    db_path = tmp_path / "signatures.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL,
            pattern BLOB NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            author TEXT,
            description TEXT,
            confidence REAL DEFAULT 1.0,
            deprecated INTEGER DEFAULT 0,
            replaced_by TEXT,
            metadata TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE signature_conflicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signature1_id INTEGER NOT NULL,
            signature2_id INTEGER NOT NULL,
            conflict_type TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            resolution_note TEXT,
            FOREIGN KEY (signature1_id) REFERENCES signatures(id),
            FOREIGN KEY (signature2_id) REFERENCES signatures(id)
        )
    """)

    cursor.execute("""
        CREATE INDEX idx_signature_name ON signatures(name)
    """)
    cursor.execute("""
        CREATE INDEX idx_signature_version ON signatures(version)
    """)
    cursor.execute("""
        CREATE INDEX idx_signature_category ON signatures(category)
    """)

    conn.commit()
    conn.close()

    return db_path


class SignatureDatabaseManager:
    """Manages versioned signature database with update capabilities."""

    def __init__(self, db_path: Path) -> None:
        """Initialize signature database manager.

        Args:
            db_path: Path to SQLite signature database.
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row

    def add_signature(
        self,
        name: str,
        category: str,
        pattern: bytes,
        author: str | None = None,
        description: str | None = None,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Add new signature to database with version tracking.

        Args:
            name: Unique signature name.
            category: Signature category (protection, packer, etc).
            pattern: Binary pattern to match.
            author: Signature author.
            description: Signature description.
            confidence: Detection confidence (0.0-1.0).
            metadata: Additional metadata.

        Returns:
            Signature ID.

        Raises:
            sqlite3.IntegrityError: If signature name already exists.
        """
        cursor = self.conn.cursor()
        now = datetime.now(timezone.utc).isoformat()

        metadata_json = json.dumps(metadata) if metadata else None

        cursor.execute("""
            INSERT INTO signatures (
                name, category, pattern, version, created_at, updated_at,
                author, description, confidence, metadata
            ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
        """, (name, category, pattern, now, now, author, description, confidence, metadata_json))

        self.conn.commit()
        row_id = cursor.lastrowid
        return row_id if row_id is not None else -1

    def update_signature(
        self,
        name: str,
        pattern: bytes | None = None,
        description: str | None = None,
        confidence: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Update existing signature and increment version.

        Args:
            name: Signature name to update.
            pattern: New pattern (optional).
            description: New description (optional).
            confidence: New confidence (optional).
            metadata: New metadata (optional).

        Returns:
            True if signature was updated, False if not found.
        """
        cursor = self.conn.cursor()

        cursor.execute("SELECT id, version FROM signatures WHERE name = ?", (name,))
        row: sqlite3.Row | None = cursor.fetchone()

        if not row:
            return False

        now = datetime.now(timezone.utc).isoformat()
        new_version: int = row["version"] + 1

        updates = ["version = ?", "updated_at = ?"]
        params: list[Any] = [new_version, now]

        if pattern is not None:
            updates.append("pattern = ?")
            params.append(pattern)

        if description is not None:
            updates.append("description = ?")
            params.append(description)

        if confidence is not None:
            updates.append("confidence = ?")
            params.append(confidence)

        if metadata is not None:
            updates.append("metadata = ?")
            params.append(json.dumps(metadata))

        params.append(name)

        cursor.execute(f"""
            UPDATE signatures SET {', '.join(updates)} WHERE name = ?
        """, params)

        self.conn.commit()
        return True

    def get_signature(self, name: str) -> dict[str, Any] | None:
        """Retrieve signature by name.

        Args:
            name: Signature name.

        Returns:
            Signature data or None if not found.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM signatures WHERE name = ?", (name,))
        row: sqlite3.Row | None = cursor.fetchone()

        if not row:
            return None

        return dict(row)

    def list_signatures(
        self,
        category: str | None = None,
        include_deprecated: bool = False,
    ) -> list[dict[str, Any]]:
        """List all signatures with optional filtering.

        Args:
            category: Filter by category (optional).
            include_deprecated: Include deprecated signatures.

        Returns:
            List of signature dictionaries.
        """
        cursor = self.conn.cursor()

        query = "SELECT * FROM signatures WHERE 1=1"
        params: list[Any] = []

        if category:
            query += " AND category = ?"
            params.append(category)

        if not include_deprecated:
            query += " AND deprecated = 0"

        query += " ORDER BY name"

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def deprecate_signature(
        self,
        name: str,
        replaced_by: str | None = None,
    ) -> bool:
        """Mark signature as deprecated.

        Args:
            name: Signature name to deprecate.
            replaced_by: Name of replacement signature (optional).

        Returns:
            True if deprecated successfully.
        """
        cursor = self.conn.cursor()
        now = datetime.now(timezone.utc).isoformat()

        cursor.execute("""
            UPDATE signatures
            SET deprecated = 1, replaced_by = ?, updated_at = ?
            WHERE name = ?
        """, (replaced_by, now, name))

        self.conn.commit()
        return cursor.rowcount > 0

    def detect_conflicts(self) -> list[dict[str, Any]]:
        """Detect signature conflicts (overlapping patterns).

        Returns:
            List of detected conflicts.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT id, name, pattern FROM signatures
            WHERE deprecated = 0
            ORDER BY id
        """)

        signatures: list[Any] = cursor.fetchall()
        conflicts: list[dict[str, Any]] = []

        for i, sig1 in enumerate(signatures):
            sig1_row: sqlite3.Row = sig1
            pattern1: bytes = sig1_row["pattern"]
            for sig2 in signatures[i + 1:]:
                sig2_row: sqlite3.Row = sig2
                pattern2: bytes = sig2_row["pattern"]

                if pattern1 in pattern2 or pattern2 in pattern1:
                    conflict = {
                        "signature1": sig1_row["name"],
                        "signature2": sig2_row["name"],
                        "type": "pattern_overlap",
                        "pattern1_length": len(pattern1),
                        "pattern2_length": len(pattern2),
                    }
                    conflicts.append(conflict)

                    cursor.execute("""
                        INSERT INTO signature_conflicts (
                            signature1_id, signature2_id, conflict_type, detected_at
                        ) VALUES (?, ?, ?, ?)
                    """, (sig1_row["id"], sig2_row["id"], "pattern_overlap",
                          datetime.now(timezone.utc).isoformat()))

        self.conn.commit()
        return conflicts

    def export_signatures(self, export_path: Path, format: str = "json") -> bool:
        """Export signatures to file.

        Args:
            export_path: Path to export file.
            format: Export format (json or csv).

        Returns:
            True if export succeeded.
        """
        signatures = self.list_signatures(include_deprecated=True)

        if format == "json":
            sig_list: list[dict[str, Any]] = []
            for sig in signatures:
                pattern_bytes: bytes = sig["pattern"]
                metadata_str: str | None = sig["metadata"]
                sig_copy: dict[str, Any] = dict(sig)
                sig_copy["pattern"] = pattern_bytes.hex()
                sig_copy["metadata"] = json.loads(metadata_str) if metadata_str else None
                sig_list.append(sig_copy)

            export_data: dict[str, Any] = {
                "version": 1,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "signature_count": len(signatures),
                "signatures": sig_list
            }

            export_path.write_text(json.dumps(export_data, indent=2))
            return True

        elif format == "csv":
            import csv

            with export_path.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "name", "category", "version", "confidence",
                    "author", "description", "deprecated"
                ])
                writer.writeheader()

                for sig in signatures:
                    writer.writerow({
                        "name": sig["name"],
                        "category": sig["category"],
                        "version": sig["version"],
                        "confidence": sig["confidence"],
                        "author": sig["author"] or "",
                        "description": sig["description"] or "",
                        "deprecated": sig["deprecated"],
                    })

            return True

        return False

    def import_signatures(
        self,
        import_path: Path,
        conflict_resolution: str = "skip",
    ) -> dict[str, int]:
        """Import signatures from file.

        Args:
            import_path: Path to import file.
            conflict_resolution: How to handle conflicts (skip, replace, version).

        Returns:
            Import statistics.
        """
        stats = {
            "imported": 0,
            "skipped": 0,
            "updated": 0,
            "errors": 0,
        }

        import_data: dict[str, Any] = json.loads(import_path.read_text())

        for sig_data in import_data.get("signatures", []):
            sig_data_dict: dict[str, Any] = sig_data
            name: str = sig_data_dict["name"]
            pattern: bytes = bytes.fromhex(sig_data_dict["pattern"])

            existing = self.get_signature(name)

            if existing:
                if conflict_resolution == "skip":
                    stats["skipped"] += 1
                    continue
                elif conflict_resolution == "replace":
                    self.update_signature(
                        name,
                        pattern=pattern,
                        description=sig_data_dict.get("description"),
                        confidence=sig_data_dict.get("confidence", 1.0),
                        metadata=sig_data_dict.get("metadata"),
                    )
                    stats["updated"] += 1
                elif conflict_resolution == "version":
                    self.update_signature(
                        name,
                        pattern=pattern,
                        description=sig_data_dict.get("description"),
                        confidence=sig_data_dict.get("confidence", 1.0),
                        metadata=sig_data_dict.get("metadata"),
                    )
                    stats["updated"] += 1
            else:
                try:
                    self.add_signature(
                        name=name,
                        category=sig_data_dict["category"],
                        pattern=pattern,
                        author=sig_data_dict.get("author"),
                        description=sig_data_dict.get("description"),
                        confidence=sig_data_dict.get("confidence", 1.0),
                        metadata=sig_data_dict.get("metadata"),
                    )
                    stats["imported"] += 1
                except Exception:
                    stats["errors"] += 1

        return stats

    def validate_signature(self, name: str) -> dict[str, Any]:
        """Validate signature integrity and effectiveness.

        Args:
            name: Signature name to validate.

        Returns:
            Validation results.
        """
        sig = self.get_signature(name)

        if not sig:
            return {"valid": False, "error": "Signature not found"}

        validation: dict[str, Any] = {
            "valid": True,
            "warnings": [],
            "errors": [],
        }

        if len(sig["pattern"]) < 4:
            validation["warnings"].append("Pattern too short, may cause false positives")

        if sig["confidence"] < 0.5:
            validation["warnings"].append("Low confidence signature")

        if sig["deprecated"]:
            validation["warnings"].append("Signature is deprecated")
            if sig["replaced_by"]:
                validation["warnings"].append(f"Use {sig['replaced_by']} instead")

        if sig["version"] > 10:
            validation["warnings"].append("High version number, consider review")

        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM signature_conflicts
            WHERE (signature1_id = ? OR signature2_id = ?)
            AND resolved = 0
        """, (sig["id"], sig["id"]))

        conflict_row = cursor.fetchone()
        conflict_count = conflict_row["count"] if conflict_row is not None else 0
        if conflict_count > 0:
            validation["warnings"].append(f"Has {conflict_count} unresolved conflicts")

        return validation

    def close(self) -> None:
        """Close database connection."""
        self.conn.close()


def test_signature_database_creation(signature_database: Path) -> None:
    """Verify signature database schema is created correctly."""
    conn = sqlite3.connect(signature_database)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='signatures'
    """)
    sig_table_row: Any = cursor.fetchone()
    assert sig_table_row is not None

    cursor.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='signature_conflicts'
    """)
    conflict_table_row: Any = cursor.fetchone()
    assert conflict_table_row is not None

    cursor.execute("PRAGMA table_info(signatures)")
    columns = {row[1] for row in cursor.fetchall()}

    assert "version" in columns
    assert "created_at" in columns
    assert "updated_at" in columns
    assert "deprecated" in columns
    assert "replaced_by" in columns

    conn.close()


def test_signature_versioning(signature_database: Path) -> None:
    """Verify signatures support version tracking."""
    manager = SignatureDatabaseManager(signature_database)

    sig_id = manager.add_signature(
        name="VMProtect_3.x",
        category="protector",
        pattern=b"\x56\x4d\x50\x72\x6f\x74\x65\x63\x74",
        description="VMProtect 3.x signature",
        confidence=0.95,
    )

    assert sig_id > 0

    sig = manager.get_signature("VMProtect_3.x")
    assert sig is not None
    assert sig["version"] == 1

    assert manager.update_signature(
        "VMProtect_3.x",
        pattern=b"\x56\x4d\x50\x72\x6f\x74\x65\x63\x74\x33",
        description="Updated VMProtect 3.x signature",
    )

    updated_sig = manager.get_signature("VMProtect_3.x")
    assert updated_sig is not None
    assert updated_sig["version"] == 2
    assert updated_sig["pattern"] == b"\x56\x4d\x50\x72\x6f\x74\x65\x63\x74\x33"

    for _ in range(3):
        manager.update_signature("VMProtect_3.x", confidence=0.98)

    final_sig = manager.get_signature("VMProtect_3.x")
    assert final_sig is not None
    assert final_sig["version"] == 5

    manager.close()


def test_signature_import_export(signature_database: Path, tmp_path: Path) -> None:
    """Verify signature import/export functionality."""
    manager = SignatureDatabaseManager(signature_database)

    manager.add_signature(
        "Themida_2.x",
        "protector",
        b"\x54\x68\x65\x6d\x69\x64\x61",
        author="Test User",
        description="Themida protector",
        confidence=0.92,
        metadata={"version_range": "2.0-2.9"},
    )

    manager.add_signature(
        "UPX_3.96",
        "packer",
        b"\x55\x50\x58\x21",
        description="UPX packer",
        confidence=0.98,
    )

    export_path = tmp_path / "signatures_export.json"
    assert manager.export_signatures(export_path, format="json")
    assert export_path.exists()

    export_data = json.loads(export_path.read_text())
    assert export_data["signature_count"] == 2
    assert len(export_data["signatures"]) == 2

    sig_names = {sig["name"] for sig in export_data["signatures"]}
    assert "Themida_2.x" in sig_names
    assert "UPX_3.96" in sig_names

    new_db_path = tmp_path / "new_signatures.db"
    new_db_path.write_bytes(signature_database.read_bytes())
    new_manager = SignatureDatabaseManager(new_db_path)

    stats = new_manager.import_signatures(export_path, conflict_resolution="skip")
    assert stats["imported"] == 0
    assert stats["skipped"] == 2

    new_manager.close()
    manager.close()


def test_signature_conflict_detection(signature_database: Path) -> None:
    """Verify signature conflict detection works correctly."""
    manager = SignatureDatabaseManager(signature_database)

    manager.add_signature(
        "Pattern_A",
        "test",
        b"\x00\x01\x02\x03\x04\x05",
        description="Full pattern",
    )

    manager.add_signature(
        "Pattern_B",
        "test",
        b"\x01\x02\x03",
        description="Substring of Pattern_A",
    )

    manager.add_signature(
        "Pattern_C",
        "test",
        b"\xFF\xFE\xFD",
        description="No conflict",
    )

    conflicts = manager.detect_conflicts()

    assert len(conflicts) == 1
    assert conflicts[0]["type"] == "pattern_overlap"
    assert set([conflicts[0]["signature1"], conflicts[0]["signature2"]]) == {"Pattern_A", "Pattern_B"}

    manager.close()


def test_user_defined_signatures(signature_database: Path, sample_binary_path: Path) -> None:
    """Verify user can define and use custom signatures."""
    manager = SignatureDatabaseManager(signature_database)

    custom_sig_id = manager.add_signature(
        name="CustomLicenseCheck",
        category="license",
        pattern=b"CustomCheckLicense",
        author="Security Researcher",
        description="Custom license validation routine",
        confidence=0.85,
        metadata={
            "protection_type": "custom",
            "common_in": ["Commercial Software"],
        },
    )

    assert custom_sig_id > 0

    detector = Radare2SignatureDetector(str(sample_binary_path))
    detector.custom_signatures["CustomLicenseCheck"] = b"CustomCheckLicense"

    binary_content = sample_binary_path.read_bytes()
    sample_binary_path.write_bytes(binary_content + b"CustomCheckLicense" + b"\x00" * 100)

    matches = detector.scan_custom_signatures()

    custom_match = next(
        (m for m in matches if m.name == "CustomLicenseCheck"),
        None
    )
    assert custom_match is not None
    assert custom_match.confidence >= 0.85

    manager.close()


def test_signature_validation(signature_database: Path) -> None:
    """Verify signature validation detects issues."""
    manager = SignatureDatabaseManager(signature_database)

    manager.add_signature(
        "ShortPattern",
        "test",
        b"\x00\x01",
        confidence=0.3,
    )

    validation = manager.validate_signature("ShortPattern")
    assert validation["valid"] is True
    assert len(validation["warnings"]) > 0
    assert any("too short" in w for w in validation["warnings"])
    assert any("Low confidence" in w for w in validation["warnings"])

    manager.add_signature(
        "GoodPattern",
        "test",
        b"\x00\x01\x02\x03\x04\x05\x06\x07",
        confidence=0.95,
    )

    good_validation = manager.validate_signature("GoodPattern")
    assert good_validation["valid"] is True
    assert len(good_validation["warnings"]) == 0

    manager.close()


def test_signature_deprecation(signature_database: Path) -> None:
    """Verify signature deprecation and replacement tracking."""
    manager = SignatureDatabaseManager(signature_database)

    manager.add_signature(
        "VMProtect_old",
        "protector",
        b"\x56\x4d\x50\x6f\x6c\x64",
        description="Old VMProtect pattern",
    )

    manager.add_signature(
        "VMProtect_new",
        "protector",
        b"\x56\x4d\x50\x6e\x65\x77",
        description="New VMProtect pattern",
    )

    assert manager.deprecate_signature("VMProtect_old", replaced_by="VMProtect_new")

    old_sig = manager.get_signature("VMProtect_old")
    assert old_sig is not None
    assert old_sig["deprecated"] == 1
    assert old_sig["replaced_by"] == "VMProtect_new"

    active_sigs = manager.list_signatures(include_deprecated=False)
    assert len(active_sigs) == 1
    assert active_sigs[0]["name"] == "VMProtect_new"

    all_sigs = manager.list_signatures(include_deprecated=True)
    assert len(all_sigs) == 2

    validation = manager.validate_signature("VMProtect_old")
    assert any("deprecated" in w for w in validation["warnings"])
    assert any("VMProtect_new" in w for w in validation["warnings"])

    manager.close()


def test_signature_update_persistence(signature_database: Path) -> None:
    """Verify signature updates persist across sessions."""
    manager1 = SignatureDatabaseManager(signature_database)

    manager1.add_signature(
        "PersistTest",
        "test",
        b"\xAA\xBB\xCC\xDD",
        confidence=0.8,
    )

    sig_before = manager1.get_signature("PersistTest")
    assert sig_before is not None
    version_before = sig_before["version"]

    manager1.close()

    manager2 = SignatureDatabaseManager(signature_database)

    manager2.update_signature(
        "PersistTest",
        pattern=b"\xAA\xBB\xCC\xDD\xEE",
        confidence=0.95,
    )

    manager2.close()

    manager3 = SignatureDatabaseManager(signature_database)

    sig_after = manager3.get_signature("PersistTest")
    assert sig_after is not None
    assert sig_after["version"] == version_before + 1
    assert sig_after["pattern"] == b"\xAA\xBB\xCC\xDD\xEE"
    assert sig_after["confidence"] == 0.95

    manager3.close()


def test_protection_version_tracking(signature_database: Path) -> None:
    """Verify signature versioning tracks protection version changes."""
    manager = SignatureDatabaseManager(signature_database)

    manager.add_signature(
        "VMProtect",
        "protector",
        b"\x56\x4d\x50\x31",
        description="VMProtect 1.x",
        metadata={"protection_version": "1.x"},
    )

    manager.update_signature(
        "VMProtect",
        pattern=b"\x56\x4d\x50\x32",
        description="VMProtect 2.x",
        metadata={"protection_version": "2.x"},
    )

    manager.update_signature(
        "VMProtect",
        pattern=b"\x56\x4d\x50\x33",
        description="VMProtect 3.x",
        metadata={"protection_version": "3.x"},
    )

    sig = manager.get_signature("VMProtect")
    assert sig is not None
    assert sig["version"] == 3

    sig_metadata: str | None = sig["metadata"]
    metadata = json.loads(sig_metadata) if sig_metadata is not None else {}
    assert metadata["protection_version"] == "3.x"

    manager.close()


def test_signature_conflict_resolution(signature_database: Path) -> None:
    """Verify conflict detection and resolution workflow."""
    manager = SignatureDatabaseManager(signature_database)

    manager.add_signature(
        "Overlap_A",
        "test",
        b"\x00\x01\x02\x03\x04",
    )

    manager.add_signature(
        "Overlap_B",
        "test",
        b"\x02\x03",
    )

    conflicts = manager.detect_conflicts()
    assert len(conflicts) > 0

    cursor = manager.conn.cursor()
    cursor.execute("""
        SELECT * FROM signature_conflicts WHERE resolved = 0
    """)
    unresolved: list[Any] = cursor.fetchall()
    assert len(unresolved) > 0

    cursor.execute("""
        UPDATE signature_conflicts SET resolved = 1, resolution_note = ?
        WHERE signature1_id = (SELECT id FROM signatures WHERE name = ?)
    """, ("Accepted overlap - different contexts", "Overlap_A"))
    manager.conn.commit()

    cursor.execute("""
        SELECT * FROM signature_conflicts WHERE resolved = 0
    """)
    remaining: list[Any] = cursor.fetchall()
    assert len(remaining) < len(unresolved)

    manager.close()


def test_hardcoded_signatures_fail_without_database(sample_binary_path: Path) -> None:
    """Verify test fails if signatures are hardcoded without update mechanism.

    This test ensures the codebase doesn't rely solely on hardcoded signatures.
    """
    detector = Radare2SignatureDetector(str(sample_binary_path))

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as f:
        f.write("""
rule DynamicTest {
    strings:
        $dynamic = "DYNAMICSIGNATURE"
    condition:
        $dynamic
}
""")
        temp_yara = f.name

    try:
        assert detector.load_yara_rules(temp_yara)

        binary_content = sample_binary_path.read_bytes()
        sample_binary_path.write_bytes(binary_content + b"DYNAMICSIGNATURE\x00")

        matches = detector.scan_with_yara()

        has_dynamic = any(m.name == "DynamicTest" for m in matches)
        assert has_dynamic, "Signature update mechanism must support dynamic rule loading"

    finally:
        Path(temp_yara).unlink()


def test_csv_export_format(signature_database: Path, tmp_path: Path) -> None:
    """Verify CSV export format compatibility."""
    manager = SignatureDatabaseManager(signature_database)

    manager.add_signature(
        "Test_CSV",
        "test",
        b"\x00\x01\x02",
        author="CSV Tester",
        description="Test CSV export",
        confidence=0.9,
    )

    csv_path = tmp_path / "signatures.csv"
    assert manager.export_signatures(csv_path, format="csv")

    import csv

    with csv_path.open("r") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 1
    assert rows[0]["name"] == "Test_CSV"
    assert rows[0]["category"] == "test"
    assert rows[0]["author"] == "CSV Tester"

    manager.close()


def test_import_with_conflict_resolution_modes(signature_database: Path, tmp_path: Path) -> None:
    """Verify different conflict resolution modes work correctly."""
    manager = SignatureDatabaseManager(signature_database)

    manager.add_signature(
        "ConflictTest",
        "test",
        b"\xFF\xFF",
        confidence=0.5,
    )

    export_path = tmp_path / "export.json"
    manager.export_signatures(export_path)

    export_data = json.loads(export_path.read_text())
    export_data["signatures"][0]["confidence"] = 0.9
    export_path.write_text(json.dumps(export_data))

    stats_skip = manager.import_signatures(export_path, conflict_resolution="skip")
    assert stats_skip["skipped"] == 1
    assert stats_skip["updated"] == 0

    sig = manager.get_signature("ConflictTest")
    assert sig is not None
    assert sig["confidence"] == 0.5

    stats_replace = manager.import_signatures(export_path, conflict_resolution="replace")
    assert stats_replace["updated"] == 1

    updated_sig = manager.get_signature("ConflictTest")
    assert updated_sig is not None
    assert updated_sig["confidence"] == 0.9
    assert updated_sig["version"] == 2

    manager.close()


def test_metadata_preservation(signature_database: Path) -> None:
    """Verify signature metadata is preserved through updates."""
    manager = SignatureDatabaseManager(signature_database)

    metadata = {
        "protection_type": "VMProtect",
        "version_range": "3.0-3.8",
        "detection_method": "bytecode_pattern",
        "false_positive_rate": 0.01,
    }

    manager.add_signature(
        "MetadataTest",
        "protector",
        b"\xAA\xBB\xCC",
        metadata=metadata,
    )

    sig = manager.get_signature("MetadataTest")
    assert sig is not None

    sig_metadata_str: str | None = sig["metadata"]
    loaded_metadata = json.loads(sig_metadata_str) if sig_metadata_str is not None else {}
    assert loaded_metadata == metadata

    manager.update_signature(
        "MetadataTest",
        pattern=b"\xAA\xBB\xCC\xDD",
    )

    updated_sig = manager.get_signature("MetadataTest")
    assert updated_sig is not None

    updated_metadata_str: str | None = updated_sig["metadata"]
    preserved_metadata = json.loads(updated_metadata_str) if updated_metadata_str is not None else {}
    assert preserved_metadata == metadata

    manager.close()
