"""Production-grade tests for SQLite3 handler.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def temp_db_file() -> Generator[Path, None, None]:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = Path(tf.name)

    yield db_path

    if db_path.exists():
        db_path.unlink()


class TestSQLite3HandlerFallbackMode:
    """Test SQLite3 handler fallback in-memory database."""

    def test_fallback_connection_creation(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        assert conn is not None
        assert conn.database == ":memory:"

        conn.close()

    def test_fallback_table_creation_and_insertion(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INTEGER)")
        cursor.execute("INSERT INTO users (id, name, age) VALUES (?, ?, ?)", [1, "Alice", 30])
        cursor.execute("INSERT INTO users VALUES (?, ?, ?)", [2, "Bob", 25])

        conn.commit()
        conn.close()

    def test_fallback_select_query_results(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE test (id INTEGER, value TEXT)")
        cursor.execute("INSERT INTO test VALUES (1, 'first')")
        cursor.execute("INSERT INTO test VALUES (2, 'second')")
        cursor.execute("INSERT INTO test VALUES (3, 'third')")

        cursor.execute("SELECT * FROM test ORDER BY id")
        results = cursor.fetchall()

        assert len(results) == 3
        assert results[0] == (1, "first")
        assert results[1] == (2, "second")
        assert results[2] == (3, "third")

        conn.close()

    def test_fallback_where_clause_filtering(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE products (id INTEGER, price REAL)")
        cursor.execute("INSERT INTO products VALUES (1, 10.5)")
        cursor.execute("INSERT INTO products VALUES (2, 25.0)")
        cursor.execute("INSERT INTO products VALUES (3, 15.75)")

        cursor.execute("SELECT * FROM products WHERE price > 15")
        results = cursor.fetchall()

        assert len(results) == 2

        conn.close()

    def test_fallback_update_operation(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE settings (key TEXT, value INTEGER)")
        cursor.execute("INSERT INTO settings VALUES ('count', 5)")

        cursor.execute("UPDATE settings SET value = 10")

        cursor.execute("SELECT value FROM settings WHERE key = 'count'")
        result = cursor.fetchone()

        assert result[0] == 10

        conn.close()

    def test_fallback_delete_operation(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE items (id INTEGER, name TEXT)")
        cursor.execute("INSERT INTO items VALUES (1, 'item1')")
        cursor.execute("INSERT INTO items VALUES (2, 'item2')")
        cursor.execute("INSERT INTO items VALUES (3, 'item3')")

        cursor.execute("DELETE FROM items")

        cursor.execute("SELECT * FROM items")
        results = cursor.fetchall()

        assert len(results) == 0

        conn.close()

    def test_fallback_primary_key_constraint(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
        cursor.execute("INSERT INTO users VALUES (1, 'Alice')")

        with pytest.raises(handler.IntegrityError):
            cursor.execute("INSERT INTO users VALUES (1, 'Bob')")

        conn.close()

    def test_fallback_unique_constraint(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE emails (id INTEGER, email TEXT UNIQUE)")
        cursor.execute("INSERT INTO emails VALUES (1, 'test@example.com')")

        with pytest.raises(handler.IntegrityError):
            cursor.execute("INSERT INTO emails VALUES (2, 'test@example.com')")

        conn.close()

    def test_fallback_not_null_constraint(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE required (id INTEGER, name TEXT NOT NULL)")

        with pytest.raises(handler.IntegrityError):
            cursor.execute("INSERT INTO required VALUES (1, NULL)")

        conn.close()

    def test_fallback_transactions_commit(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE logs (message TEXT)")

        cursor.execute("BEGIN")
        cursor.execute("INSERT INTO logs VALUES ('entry1')")
        cursor.execute("INSERT INTO logs VALUES ('entry2')")
        cursor.execute("COMMIT")

        cursor.execute("SELECT * FROM logs")
        results = cursor.fetchall()
        assert len(results) == 2

        conn.close()

    def test_fallback_transactions_rollback(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE logs (message TEXT)")
        cursor.execute("INSERT INTO logs VALUES ('permanent')")
        conn.commit()

        cursor.execute("BEGIN")
        cursor.execute("INSERT INTO logs VALUES ('temporary')")
        cursor.execute("ROLLBACK")

        cursor.execute("SELECT * FROM logs")
        results = cursor.fetchall()
        assert len(results) == 1
        assert results[0][0] == "permanent"

        conn.close()

    def test_fallback_cursor_fetchone(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE test (value INTEGER)")
        cursor.execute("INSERT INTO test VALUES (100)")
        cursor.execute("INSERT INTO test VALUES (200)")

        cursor.execute("SELECT * FROM test")

        first = cursor.fetchone()
        assert first is not None
        assert first[0] == 100

        second = cursor.fetchone()
        assert second is not None
        assert second[0] == 200

        third = cursor.fetchone()
        assert third is None

        conn.close()

    def test_fallback_cursor_fetchmany(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE numbers (n INTEGER)")
        for i in range(10):
            cursor.execute("INSERT INTO numbers VALUES (?)", [i])

        cursor.execute("SELECT * FROM numbers")

        batch = cursor.fetchmany(3)
        assert len(batch) == 3

        conn.close()

    def test_fallback_executemany(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE batch (id INTEGER, name TEXT)")

        data = [[1, "first"], [2, "second"], [3, "third"]]
        cursor.executemany("INSERT INTO batch VALUES (?, ?)", data)

        cursor.execute("SELECT * FROM batch")
        results = cursor.fetchall()
        assert len(results) == 3

        conn.close()

    def test_fallback_drop_table(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        conn = handler.connect(":memory:")
        cursor = conn.cursor()

        cursor.execute("CREATE TABLE temp (id INTEGER)")

        cursor.execute("DROP TABLE temp")

        with pytest.raises(handler.OperationalError):
            cursor.execute("SELECT * FROM temp")

        conn.close()

    def test_fallback_file_persistence(self, temp_db_file: Path) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        if not handler.HAS_SQLITE3:
            conn1 = handler.connect(str(temp_db_file))
            cursor1 = conn1.cursor()

            cursor1.execute("CREATE TABLE persistent (id INTEGER, value TEXT)")
            cursor1.execute("INSERT INTO persistent VALUES (1, 'saved')")
            conn1.commit()
            conn1.close()

            conn2 = handler.connect(str(temp_db_file))
            cursor2 = conn2.cursor()

            cursor2.execute("SELECT * FROM persistent")
            results = cursor2.fetchall()

            assert len(results) == 1
            assert results[0] == (1, "saved")

            conn2.close()


class TestSQLite3HandlerRealMode:
    """Test SQLite3 handler with real sqlite3 (if available)."""

    def test_real_sqlite3_detection(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        if handler.HAS_SQLITE3:
            assert handler.SQLITE3_VERSION is not None
            assert handler.connect is not None

    def test_all_exception_classes_available(self) -> None:
        import intellicrack.handlers.sqlite3_handler as handler

        assert handler.Error is not None
        assert handler.DatabaseError is not None
        assert handler.IntegrityError is not None
        assert handler.OperationalError is not None
        assert handler.ProgrammingError is not None
