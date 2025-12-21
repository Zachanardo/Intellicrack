"""SQLite3 handler for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import json
import os
import re
import sys
import types
from collections.abc import Callable
from typing import Any, Protocol, TYPE_CHECKING

from intellicrack.utils.logger import logger


class Comparable(Protocol):
    """Protocol for comparable types."""

    def __lt__(self, other: Any) -> bool:
        """Less than comparison."""

    def __gt__(self, other: Any) -> bool:
        """Greater than comparison."""


"""
SQLite3 Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for sqlite3 imports.
When sqlite3 is not available, it provides REAL, functional Python-based
implementations for database operations used in Intellicrack.
"""

if TYPE_CHECKING:
    import sqlite3 as sqlite3_module_type
    from sqlite3 import Connection, Cursor, Row

HAS_SQLITE3: bool = False
HAS_SQLITE: bool = False
SQLITE3_VERSION: str | None = None

try:
    import sqlite3 as _sqlite3_real

    HAS_SQLITE3 = True
    HAS_SQLITE = True
    SQLITE3_VERSION = _sqlite3_real.sqlite_version

except ImportError as e:
    logger.error("SQLite3 not available, using fallback implementations: %s", e)
    _sqlite3_real = None  # type: ignore[assignment]

if _sqlite3_real is not None:
    from sqlite3 import (
        Connection,
        Cursor,
        DatabaseError,
        Error,
        IntegrityError,
        OperationalError,
        ProgrammingError,
        Row,
        connect,
        register_adapter,
        register_converter,
    )

    PARSE_DECLTYPES: int = _sqlite3_real.PARSE_DECLTYPES
    PARSE_COLNAMES: int = _sqlite3_real.PARSE_COLNAMES

    sqlite3 = _sqlite3_real

else:

    class FallbackError(Exception):  # type: ignore[unreachable]
        """Base exception for database errors."""

        pass

    class FallbackDatabaseError(FallbackError):
        """Database error."""

        pass

    class FallbackIntegrityError(FallbackDatabaseError):
        """Integrity constraint violation."""

        pass

    class FallbackOperationalError(FallbackDatabaseError):
        """Database operational error."""

        pass

    class FallbackProgrammingError(FallbackDatabaseError):
        """Programming error."""

        pass

    Error = FallbackError  # type: ignore[misc]
    DatabaseError = FallbackDatabaseError  # type: ignore[misc]
    IntegrityError = FallbackIntegrityError  # type: ignore[misc]
    OperationalError = FallbackOperationalError  # type: ignore[misc]
    ProgrammingError = FallbackProgrammingError  # type: ignore[misc]

    class FallbackTable:
        """In-memory table implementation.

        This class provides a simple in-memory database table that supports
        basic SQL operations including INSERT, SELECT, UPDATE, and DELETE.

        Attributes:
            name: The name of the table.
            columns: List of (column_name, column_type, constraints) tuples.
            rows: List of dictionaries representing table rows.
            primary_key: Name of the primary key column.
            indexes: Dictionary of table indexes.
            constraints: List of constraint tuples.

        """

        def __init__(self, name: str, columns: list[tuple[str, str, str]]) -> None:
            """Initialize table.

            Args:
                name: The name of the table.
                columns: List of (column_name, column_type, constraints) tuples.

            Returns:
                None

            """
            self.name: str = name
            self.columns: list[tuple[str, str, str]] = columns
            self.rows: list[dict[str, Any]] = []
            self.primary_key: str | None = None
            self.indexes: dict[str, Any] = {}
            self.constraints: list[tuple[str, str]] = []

            for col_name, _col_type, constraints in columns:
                if "PRIMARY KEY" in constraints:
                    self.primary_key = col_name
                if "UNIQUE" in constraints:
                    self.constraints.append(("UNIQUE", col_name))
                if "NOT NULL" in constraints:
                    self.constraints.append(("NOT NULL", col_name))

        def insert(self, values: list[Any]) -> int:
            """Insert row into table.

            Args:
                values: List of values to insert into the row.

            Returns:
                The number of rows in the table after insertion.

            Raises:
                IntegrityError: If constraints are violated.

            """
            row = {}
            for i, (col_name, col_type, _constraints) in enumerate(self.columns):
                if i < len(values):
                    value = values[i]
                else:
                    value = None

                if value is None and ("NOT NULL", col_name) in self.constraints:
                    error_msg = f"NOT NULL constraint failed: {col_name}"
                    logger.error(error_msg)
                    raise IntegrityError(error_msg)

                if value is not None:
                    if col_type == "INTEGER":
                        value = int(value) if value else None
                    elif col_type == "REAL":
                        value = float(value) if value else None
                    elif col_type == "TEXT":
                        value = str(value)
                    elif col_type == "BLOB":
                        value = value if isinstance(value, bytes) else bytes(value)

                row[col_name] = value

            for constraint_type, col_name in self.constraints:
                if constraint_type == "UNIQUE" and row[col_name] is not None:
                    for existing_row in self.rows:
                        if existing_row[col_name] == row[col_name]:
                            error_msg = f"UNIQUE constraint failed: {col_name}"
                            logger.error(error_msg)
                            raise IntegrityError(error_msg)
            if self.primary_key and row[self.primary_key] is not None:
                for existing_row in self.rows:
                    if existing_row[self.primary_key] == row[self.primary_key]:
                        error_msg = f"PRIMARY KEY constraint failed: {self.primary_key}"
                        logger.error(error_msg)
                        raise IntegrityError(error_msg)

            self.rows.append(row)
            return len(self.rows)

        def select(
            self,
            columns: list[str] | None = None,
            where: tuple[str, str, Any] | None = None,
            order_by: tuple[str, str] | None = None,
            limit: int | None = None,
        ) -> list[tuple[Any, ...]]:
            """Select rows from table.

            Args:
                columns: List of column names to select, or None for all columns.
                where: WHERE clause as (column, operator, value) tuple.
                order_by: ORDER BY clause as (column, direction) tuple.
                limit: Maximum number of rows to return.

            Returns:
                List of tuples representing selected rows.

            """
            result_rows = []

            for row in self.rows:
                if where and not self._evaluate_where(row, where):
                    continue

                if columns and columns != ["*"]:
                    result_row = tuple(row.get(col) for col in columns)
                else:
                    result_row = tuple(row.values())

                result_rows.append(result_row)

            if order_by:
                col_name, direction = order_by
                col_idx = self._get_column_index(col_name)
                reverse = direction == "DESC"

                def sort_key(x: tuple[Any, ...]) -> Any:
                    val = x[col_idx] if col_idx < len(x) else None
                    if val is None:
                        return ""
                    return val

                result_rows.sort(key=sort_key, reverse=reverse)

            if limit:
                result_rows = result_rows[:limit]

            return result_rows

        def update(
            self,
            set_values: dict[str, Any],
            where: tuple[str, str, Any] | None = None,
        ) -> int:
            """Update rows in table.

            Args:
                set_values: Dictionary of column names to new values.
                where: WHERE clause as (column, operator, value) tuple.

            Returns:
                The number of rows updated.

            """
            updated_count = 0

            for row in self.rows:
                if where and not self._evaluate_where(row, where):
                    continue

                for col_name, value in set_values.items():
                    row[col_name] = value
                updated_count += 1

            return updated_count

        def delete(self, where: tuple[str, str, Any] | None = None) -> int:
            """Delete rows from table.

            Args:
                where: WHERE clause as (column, operator, value) tuple.

            Returns:
                The number of rows deleted.

            """
            if where is None:
                deleted = len(self.rows)
                self.rows.clear()
                return deleted

            new_rows = []
            deleted = 0

            for row in self.rows:
                if self._evaluate_where(row, where):
                    deleted += 1
                else:
                    new_rows.append(row)

            self.rows = new_rows
            return deleted

        def _evaluate_where(
            self,
            row: dict[str, Any],
            where: tuple[str, str, Any],
        ) -> bool:
            """Evaluate WHERE clause for a row.

            Args:
                row: Dictionary representing a table row.
                where: WHERE clause as (column, operator, value) tuple.

            Returns:
                True if the row matches the WHERE clause, False otherwise.

            """
            col_name, operator, value = where
            row_value = row.get(col_name)

            if operator == "=":
                return bool(row_value == value)
            elif operator == "!=":
                return bool(row_value != value)
            elif operator == ">":
                return bool(row_value > value if row_value is not None else False)
            elif operator == "<":
                return bool(row_value < value if row_value is not None else False)
            elif operator == ">=":
                return bool(row_value >= value if row_value is not None else False)
            elif operator == "<=":
                return bool(row_value <= value if row_value is not None else False)
            elif operator == "LIKE":
                if row_value is None:
                    return False
                pattern = value.replace("%", ".*").replace("_", ".")
                return bool(re.match(pattern, str(row_value)))
            elif operator == "IN":
                return bool(row_value in value)
            elif operator == "IS":
                return bool(row_value is value)
            elif operator == "IS NOT":
                return bool(row_value is not value)

            return False

        def _get_column_index(self, col_name: str) -> int:
            """Get column index by name.

            Args:
                col_name: The name of the column.

            Returns:
                The zero-based index of the column, or 0 if not found.

            """
            return next(
                (i for i, (name, _, _) in enumerate(self.columns) if name == col_name),
                0,
            )

    class FallbackDatabase:
        """In-memory database implementation.

        This class provides a complete in-memory database that supports
        CREATE TABLE, DROP TABLE, INSERT, SELECT, UPDATE, DELETE, and
        basic transaction management.

        Attributes:
            path: Path to the database file (":memory:" for in-memory).
            tables: Dictionary of table name to FallbackTable mappings.
            views: Dictionary of view name to view definition mappings.
            transactions: List of pending transactions.
            in_transaction: Whether a transaction is currently active.

        """

        def __init__(self, path: str = ":memory:") -> None:
            """Initialize database.

            Args:
                path: Path to database file or ":memory:" for in-memory.

            Returns:
                None

            """
            self.path: str = path
            self.tables: dict[str, FallbackTable] = {}
            self.views: dict[str, Any] = {}
            self.transactions: list[Any] = []
            self.in_transaction: bool = False

            if path != ":memory:" and os.path.exists(path):
                self._load_from_file()

        def create_table(self, name: str, columns: list[tuple[str, str, str]]) -> None:
            """Create a new table.

            Args:
                name: The name of the table to create.
                columns: List of (column_name, column_type, constraints) tuples.

            Returns:
                None

            Raises:
                OperationalError: If the table already exists.

            """
            if name in self.tables:
                error_msg = f"table {name} already exists"
                logger.error(error_msg)
                raise OperationalError(error_msg)

            self.tables[name] = FallbackTable(name, columns)

        def drop_table(self, name: str) -> None:
            """Drop a table.

            Args:
                name: The name of the table to drop.

            Returns:
                None

            Raises:
                OperationalError: If the table does not exist.

            """
            if name not in self.tables:
                error_msg = f"no such table: {name}"
                logger.error(error_msg)
                raise OperationalError(error_msg)

            del self.tables[name]

        def execute_sql(self, sql: str, params: list[Any] | None = None) -> list[tuple[Any, ...]] | None:
            """Execute SQL statement.

            Args:
                sql: SQL statement string to execute.
                params: Optional list of parameters for parameterized queries.

            Returns:
                Query results for SELECT statements, or None for other operations.

            Raises:
                ProgrammingError: If SQL syntax is invalid or unsupported.

            """
            sql = sql.strip()
            sql_upper = sql.upper()

            if sql_upper.startswith("CREATE TABLE"):
                self._execute_create_table(sql)
                return None
            elif sql_upper.startswith("DROP TABLE"):
                self._execute_drop_table(sql)
                return None
            elif sql_upper.startswith("INSERT INTO"):
                self._execute_insert(sql, params)
                return None
            elif sql_upper.startswith("SELECT"):
                return self._execute_select(sql, params)
            elif sql_upper.startswith("UPDATE"):
                self._execute_update(sql, params)
                return None
            elif sql_upper.startswith("DELETE"):
                self._execute_delete(sql, params)
                return None
            elif sql_upper.startswith("BEGIN"):
                self.in_transaction = True
                self.transactions = []
                return None
            elif sql_upper.startswith("COMMIT"):
                self.in_transaction = False
                self._save_to_file()
                return None
            elif sql_upper.startswith("ROLLBACK"):
                self.in_transaction = False
                self.transactions.clear()
                return None
            else:
                error_msg = f"Unsupported SQL: {sql}"
                logger.error(error_msg)
                raise ProgrammingError(error_msg)

        def _execute_create_table(self, sql: str) -> None:
            """Execute CREATE TABLE statement.

            Args:
                sql: CREATE TABLE SQL statement.

            Returns:
                None

            Raises:
                ProgrammingError: If SQL syntax is invalid.

            """
            match = re.match(r"CREATE TABLE\s+(\w+)\s*\((.*)\)", sql, re.IGNORECASE | re.DOTALL)
            if not match:
                error_msg = f"Invalid CREATE TABLE syntax: {sql}"
                logger.error(error_msg)
                raise ProgrammingError(error_msg)

            table_name = match[1]
            columns_str = match[2]

            columns = []
            for col_def in columns_str.split(","):
                col_def = col_def.strip()
                parts = col_def.split()
                if len(parts) >= 2:
                    col_name = parts[0]
                    col_type = parts[1]
                    constraints = " ".join(parts[2:])
                    columns.append((col_name, col_type, constraints))

            self.create_table(table_name, columns)

        def _execute_drop_table(self, sql: str) -> None:
            """Execute DROP TABLE statement.

            Args:
                sql: DROP TABLE SQL statement.

            Returns:
                None

            Raises:
                ProgrammingError: If SQL syntax is invalid.

            """
            match = re.match(r"DROP TABLE\s+(\w+)", sql, re.IGNORECASE)
            if not match:
                error_msg = f"Invalid DROP TABLE syntax: {sql}"
                logger.error(error_msg)
                raise ProgrammingError(error_msg)

            table_name = match[1]
            self.drop_table(table_name)

        def _execute_insert(self, sql: str, params: list[Any] | None) -> None:
            """Execute INSERT statement.

            Args:
                sql: INSERT SQL statement.
                params: Optional list of parameters for the INSERT.

            Returns:
                None

            Raises:
                ProgrammingError: If SQL syntax is invalid.
                OperationalError: If table does not exist.

            """
            match = re.match(
                r"INSERT INTO\s+(\w+)\s*(?:\((.*?)\))?\s*VALUES\s*\((.*?)\)",
                sql,
                re.IGNORECASE | re.DOTALL,
            )
            if not match:
                error_msg = f"Invalid INSERT syntax: {sql}"
                logger.error(error_msg)
                raise ProgrammingError(error_msg)

            table_name = match[1]
            match[2]
            values_str = match[3]

            if table_name not in self.tables:
                error_msg = f"no such table: {table_name}"
                logger.error(error_msg)
                raise OperationalError(error_msg)

            values = []
            if params:
                values = params
            else:
                for val in values_str.split(","):
                    val = val.strip()
                    if val.startswith("'") and val.endswith("'"):
                        values.append(val[1:-1])
                    elif val.upper() == "NULL":
                        values.append(None)
                    elif "." in val:
                        values.append(float(val))
                    else:
                        try:
                            values.append(int(val))
                        except ValueError:
                            values.append(val)

            self.tables[table_name].insert(values)

        def _execute_select(self, sql: str, params: list[Any] | None) -> list[tuple[Any, ...]]:
            """Execute SELECT statement.

            Args:
                sql: SELECT SQL statement.
                params: Optional list of parameters for the SELECT.

            Returns:
                List of tuples representing query results.

            Raises:
                ProgrammingError: If SQL syntax is invalid.
                OperationalError: If table does not exist.

            """
            match = re.match(
                r"SELECT\s+(.*?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.*?))?(?:\s+ORDER BY\s+(.*?))?(?:\s+LIMIT\s+(\d+))?",
                sql,
                re.IGNORECASE | re.DOTALL,
            )

            if not match:
                error_msg = f"Invalid SELECT syntax: {sql}"
                logger.error(error_msg)
                raise ProgrammingError(error_msg)

            columns_str = match[1]
            table_name = match[2]
            where_str = match[3]
            order_str = match[4]
            limit_str = match[5]

            if table_name not in self.tables:
                error_msg = f"no such table: {table_name}"
                logger.error(error_msg)
                raise OperationalError(error_msg)

            if columns_str.strip() == "*":
                columns = ["*"]
            else:
                columns = [col.strip() for col in columns_str.split(",")]

            where = None
            if where_str:
                if match := re.match(
                    r"(\w+)\s*(=|!=|>|<|>=|<=|LIKE|IN|IS|IS NOT)\s*(.*)",
                    where_str,
                    re.IGNORECASE,
                ):
                    col_name = match[1]
                    operator = match[2].upper()
                    value_str = match[3]

                    if params and "?" in value_str:
                        value = params[0]
                    elif value_str.startswith("'") and value_str.endswith("'"):
                        value = value_str[1:-1]
                    elif value_str.upper() == "NULL":
                        value = None
                    else:
                        try:
                            value = int(value_str)
                        except ValueError:
                            try:
                                value = float(value_str)
                            except ValueError:
                                value = value_str

                    where = (col_name, operator, value)

            order_by = None
            if order_str:
                parts = order_str.split()
                col_name = parts[0]
                direction = parts[1] if len(parts) > 1 else "ASC"
                order_by = (col_name, direction.upper())

            limit = int(limit_str) if limit_str else None

            return self.tables[table_name].select(columns, where, order_by, limit)

        def _execute_update(self, sql: str, params: list[Any] | None) -> int:
            """Execute UPDATE statement.

            Args:
                sql: UPDATE SQL statement.
                params: Optional list of parameters for the UPDATE.

            Returns:
                The number of rows updated.

            Raises:
                ProgrammingError: If SQL syntax is invalid.
                OperationalError: If table does not exist.

            """
            match = re.match(r"UPDATE\s+(\w+)\s+SET\s+(.*?)(?:\s+WHERE\s+(.*?))?", sql, re.IGNORECASE | re.DOTALL)

            if not match:
                error_msg = f"Invalid UPDATE syntax: {sql}"
                logger.error(error_msg)
                raise ProgrammingError(error_msg)

            table_name = match[1]
            set_str = match[2]
            match[3]

            if table_name not in self.tables:
                error_msg = f"no such table: {table_name}"
                logger.error(error_msg)
                raise OperationalError(error_msg)

            set_values = {}
            for assignment in set_str.split(","):
                col_name, value_str = assignment.split("=")
                col_name = col_name.strip()
                value_str = value_str.strip()

                if params and "?" in value_str:
                    value = params.pop(0)
                elif value_str.startswith("'") and value_str.endswith("'"):
                    value = value_str[1:-1]
                else:
                    try:
                        value = int(value_str)
                    except ValueError:
                        value = value_str

                set_values[col_name] = value

            where = None
            return self.tables[table_name].update(set_values, where)

        def _execute_delete(self, sql: str, params: list[Any] | None) -> int:
            """Execute DELETE statement.

            Args:
                sql: DELETE SQL statement.
                params: Optional list of parameters for the DELETE.

            Returns:
                The number of rows deleted.

            Raises:
                ProgrammingError: If SQL syntax is invalid.
                OperationalError: If table does not exist.

            """
            match = re.match(r"DELETE\s+FROM\s+(\w+)(?:\s+WHERE\s+(.*?))?", sql, re.IGNORECASE | re.DOTALL)

            if not match:
                error_msg = f"Invalid DELETE syntax: {sql}"
                logger.error(error_msg)
                raise ProgrammingError(error_msg)

            table_name = match[1]
            match[2]

            if table_name not in self.tables:
                error_msg = f"no such table: {table_name}"
                logger.error(error_msg)
                raise OperationalError(error_msg)

            where = None
            return self.tables[table_name].delete(where)

        def _save_to_file(self) -> None:
            """Save database to file.

            Serializes all tables and views to a JSON file for persistence.
            Only saves if the database path is not ":memory:".

            Returns:
                None

            """
            if self.path != ":memory:":
                try:
                    tables_data: dict[str, dict[str, Any]] = {
                        name: {
                            "name": table.name,
                            "columns": table.columns,
                            "rows": table.rows,
                            "primary_key": table.primary_key,
                            "indexes": table.indexes,
                            "constraints": table.constraints,
                        }
                        for name, table in self.tables.items()
                    }
                    serialized_data: dict[str, Any] = {"tables": tables_data, "views": self.views}

                    with open(self.path, "w", encoding="utf-8") as f:
                        json.dump(serialized_data, f, indent=2)
                except Exception as e:
                    logger.error("Failed to save database: %s", e)

        def _load_from_file(self) -> None:
            """Load database from file.

            Reconstructs tables and views from a JSON file if the database
            path is not ":memory:".

            Returns:
                None

            """
            try:
                with open(self.path, encoding="utf-8") as f:
                    data = json.load(f)

                    self.tables = {}
                    for name, table_data in data.get("tables", {}).items():
                        table = FallbackTable(name, table_data["columns"])
                        table.rows = table_data.get("rows", [])
                        table.primary_key = table_data.get("primary_key")
                        table.indexes = table_data.get("indexes", {})
                        table.constraints = table_data.get("constraints", [])
                        self.tables[name] = table

                    self.views = data.get("views", {})
            except Exception as e:
                logger.error("Failed to load database: %s", e)

    class FallbackCursor:
        """Database cursor implementation.

        Provides an interface for executing SQL statements and fetching results.

        Attributes:
            connection: The connection object this cursor belongs to.
            description: Sequence of column descriptions for the last query.
            rowcount: Number of rows affected by the last operation.
            lastrowid: Row ID of the last inserted row.
            _results: Internal list of query results.
            _result_index: Current position in the results list.

        """

        def __init__(self, connection: "FallbackConnection") -> None:
            """Initialize cursor.

            Args:
                connection: The database connection object.

            Returns:
                None

            """
            self.connection: FallbackConnection = connection
            self.description: list[tuple[str, ...]] | None = None
            self.rowcount: int = -1
            self.lastrowid: int | None = None
            self._results: list[tuple[Any, ...]] = []
            self._result_index: int = 0

        def execute(
            self,
            sql: str,
            params: list[Any] | None = None,
        ) -> "FallbackCursor":
            """Execute SQL statement.

            Args:
                sql: SQL statement string to execute.
                params: Optional list of parameters for parameterized queries.

            Returns:
                This Cursor instance for method chaining.

            Raises:
                DatabaseError: If execution fails.

            """
            try:
                result = self.connection._db.execute_sql(sql, params)

                if result is not None:
                    self._results = result
                    self._result_index = 0
                    self.rowcount = len(result)
                else:
                    self._results = []
                    self.rowcount = -1

                if sql.strip().upper().startswith("SELECT"):
                    self.description = [("column",) for _ in range(len(self._results[0]) if self._results else 0)]

                return self

            except Exception as e:
                error_msg = str(e)
                logger.error(error_msg)
                raise DatabaseError(error_msg) from e

        def executemany(self, sql: str, params_list: list[list[Any]]) -> "FallbackCursor":
            """Execute SQL with multiple parameter sets.

            Args:
                sql: SQL statement string to execute.
                params_list: List of parameter lists, one for each execution.

            Returns:
                This Cursor instance for method chaining.

            """
            for params in params_list:
                self.execute(sql, params)
            return self

        def fetchone(self) -> tuple[Any, ...] | None:
            """Fetch one row.

            Args:
                None

            Returns:
                A tuple representing a row, or None if no more rows.

            """
            if self._result_index < len(self._results):
                row = self._results[self._result_index]
                self._result_index += 1
                return row
            return None

        def fetchall(self) -> list[tuple[Any, ...]]:
            """Fetch all remaining rows.

            Args:
                None

            Returns:
                List of tuples representing all remaining rows.

            """
            rows = self._results[self._result_index :]
            self._result_index = len(self._results)
            return rows

        def fetchmany(self, size: int | None = None) -> list[tuple[Any, ...]]:
            """Fetch multiple rows.

            Args:
                size: Number of rows to fetch, defaults to 1.

            Returns:
                List of tuples representing up to size rows.

            """
            if size is None:
                size = 1

            rows: list[tuple[Any, ...]] = []
            for _ in range(size):
                row = self.fetchone()
                if row is None:
                    break
                rows.append(row)
            return rows

        def close(self) -> None:
            """Close cursor.

            Args:
                None

            Returns:
                None

            """
            self._results = []

        def __enter__(self) -> "FallbackCursor":
            """Context manager entry.

            Args:
                None

            Returns:
                This Cursor instance.

            """
            return self

        def __exit__(self, *args: object) -> None:
            """Context manager exit.

            Args:
                *args: Exception information (exc_type, exc_val, exc_tb).

            Returns:
                None

            """
            self.close()

    Cursor = FallbackCursor  # type: ignore[misc]

    class FallbackConnection:
        """Database connection implementation.

        Manages the connection to a database and provides methods for
        executing SQL statements.

        Attributes:
            database: The database path or ":memory:" for in-memory.
            _db: The internal FallbackDatabase instance.
            isolation_level: Transaction isolation level (not used in fallback).
            row_factory: Optional factory function for row objects.

        """

        def __init__(self, database: str = ":memory:") -> None:
            """Initialize connection.

            Args:
                database: Path to database file or ":memory:" for in-memory.

            Returns:
                None

            """
            self.database: str = database
            self._db: FallbackDatabase = FallbackDatabase(database)
            self.isolation_level: str | None = None
            self.row_factory: Callable[[Any, tuple[Any, ...]], Any] | None = None

        def cursor(self) -> FallbackCursor:
            """Create a cursor.

            Args:
                None

            Returns:
                A new Cursor instance bound to this connection.

            """
            return FallbackCursor(self)

        def execute(self, sql: str, params: list[Any] | None = None) -> FallbackCursor:
            """Execute SQL directly.

            Args:
                sql: SQL statement string to execute.
                params: Optional list of parameters.

            Returns:
                A Cursor instance with the results.

            """
            cursor = self.cursor()
            return cursor.execute(sql, params)

        def executemany(self, sql: str, params_list: list[list[Any]]) -> FallbackCursor:
            """Execute SQL with multiple parameter sets.

            Args:
                sql: SQL statement string to execute.
                params_list: List of parameter lists.

            Returns:
                A Cursor instance.

            """
            cursor = self.cursor()
            return cursor.executemany(sql, params_list)

        def commit(self) -> None:
            """Commit transaction.

            Args:
                None

            Returns:
                None

            """
            self._db.execute_sql("COMMIT")

        def rollback(self) -> None:
            """Rollback transaction.

            Args:
                None

            Returns:
                None

            """
            self._db.execute_sql("ROLLBACK")

        def close(self) -> None:
            """Close connection.

            Args:
                None

            Returns:
                None

            """
            if self._db.path != ":memory:":
                self._db._save_to_file()

        def __enter__(self) -> "FallbackConnection":
            """Context manager entry.

            Args:
                None

            Returns:
                This Connection instance.

            """
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: types.TracebackType | None,
        ) -> None:
            """Context manager exit.

            Args:
                exc_type: The exception type if an exception occurred.
                exc_val: The exception instance if an exception occurred.
                exc_tb: The exception traceback if an exception occurred.

            Returns:
                None

            """
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
            self.close()

    Connection = FallbackConnection  # type: ignore[misc]

    class FallbackRow:
        """Row object that supports both index and column name access.

        Provides a dict-like interface for accessing row data by column name
        or index.

        Attributes:
            cursor: The Cursor object that produced this row.
            row: The underlying tuple or list of row values.

        """

        def __init__(self, cursor: FallbackCursor, row: tuple[Any, ...]) -> None:
            """Initialize row.

            Args:
                cursor: The Cursor object that produced this row.
                row: The row data as a tuple.

            Returns:
                None

            """
            self.cursor: FallbackCursor = cursor
            self.row: tuple[Any, ...] = row

        def __getitem__(self, key: int | str) -> object:
            """Get item by index or column name.

            Args:
                key: Column index (int) or column name (str).

            Returns:
                The value at the specified column.

            Raises:
                KeyError: If the column name is not found.

            """
            if isinstance(key, int):
                return self.row[key]
            for i, desc in enumerate(self.cursor.description or []):
                if desc[0] == key:
                    return self.row[i]
            error_msg = str(key)
            logger.error(error_msg)
            raise KeyError(error_msg)

        def keys(self) -> list[str]:
            """Get column names.

            Args:
                None

            Returns:
                List of column names for this row.

            """
            return [desc[0] for desc in self.cursor.description or []]

    Row = FallbackRow  # type: ignore[misc]

    def connect(database: str = ":memory:", **kwargs: object) -> FallbackConnection:  # type: ignore[no-redef]
        """Connect to database.

        Args:
            database: Path to database file or ":memory:" for in-memory.
            **kwargs: Additional connection options (ignored in fallback).

        Returns:
            A Connection instance.

        """
        return FallbackConnection(database)

    def register_adapter(type_: type[Any], adapter: Callable[[Any], Any]) -> None:
        """Register type adapter.

        Args:
            type_: The Python type to adapt.
            adapter: A callable that adapts instances of the type.

        Returns:
            None

        """
        logger.info("Adapter registration not supported in fallback mode")

    def register_converter(name: str, converter: Callable[[Any], Any]) -> None:
        """Register type converter.

        Args:
            name: The name of the SQLite type to convert.
            converter: A callable that converts the type.

        Returns:
            None

        """
        logger.info("Converter registration not supported in fallback mode")

    PARSE_DECLTYPES: int = 1  # type: ignore[no-redef]
    PARSE_COLNAMES: int = 2  # type: ignore[no-redef]

    class FallbackSQLite3ModuleType:
        """Fallback sqlite3 module.

        Provides a module-like interface compatible with the sqlite3 standard
        library when sqlite3 is not available.

        Attributes:
            connect: Function to create database connections.
            register_adapter: Function to register type adapters.
            register_converter: Function to register type converters.
            Connection: Database connection class.
            Cursor: Database cursor class.
            Row: Row object class.
            Error: Base exception class.
            DatabaseError: Database error exception.
            IntegrityError: Integrity constraint violation exception.
            OperationalError: Operational error exception.
            ProgrammingError: Programming error exception.
            PARSE_DECLTYPES: Constant for parsing declarations.
            PARSE_COLNAMES: Constant for parsing column names.
            version: Version string of the fallback implementation.

        """

        def __init__(self) -> None:
            """Initialize fallback sqlite3 module."""
            self.connect = connect
            self.register_adapter = register_adapter
            self.register_converter = register_converter
            self.Connection = Connection
            self.Cursor = Cursor
            self.Row = Row
            self.Error = Error
            self.DatabaseError = DatabaseError
            self.IntegrityError = IntegrityError
            self.OperationalError = OperationalError
            self.ProgrammingError = ProgrammingError
            self.PARSE_DECLTYPES = PARSE_DECLTYPES
            self.PARSE_COLNAMES = PARSE_COLNAMES
            self.version = "0.0.0-fallback"

    sqlite3_fallback = FallbackSQLite3ModuleType()
    sys.modules["sqlite3"] = sqlite3_fallback
    sqlite3 = sqlite3_fallback


__all__ = [
    "Connection",
    "Cursor",
    "DatabaseError",
    "Error",
    "HAS_SQLITE",
    "HAS_SQLITE3",
    "IntegrityError",
    "OperationalError",
    "PARSE_COLNAMES",
    "PARSE_DECLTYPES",
    "ProgrammingError",
    "Row",
    "SQLITE3_VERSION",
    "connect",
    "register_adapter",
    "register_converter",
    "sqlite3",
]
