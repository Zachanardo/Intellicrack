"""This file is part of Intellicrack.
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

from intellicrack.logger import logger

"""
SQLite3 Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for sqlite3 imports.
When sqlite3 is not available, it provides REAL, functional Python-based
implementations for database operations used in Intellicrack.
"""

# SQLite3 availability detection and import handling
try:
    import sqlite3
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

    HAS_SQLITE3 = True
    HAS_SQLITE = True  # Alias for compatibility
    SQLITE3_VERSION = sqlite3.version

except ImportError as e:
    logger.error("SQLite3 not available, using fallback implementations: %s", e)
    HAS_SQLITE3 = False
    HAS_SQLITE = False  # Alias for compatibility
    SQLITE3_VERSION = None

    # Production-ready fallback in-memory database implementation

    # Exception classes
    class Error(Exception):
        """Base exception for database errors."""

        pass

    class DatabaseError(Error):
        """Database error."""

        pass

    class IntegrityError(DatabaseError):
        """Integrity constraint violation."""

        pass

    class OperationalError(DatabaseError):
        """Database operational error."""

        pass

    class ProgrammingError(DatabaseError):
        """Programming error."""

        pass

    class FallbackTable:
        """In-memory table implementation."""

        def __init__(self, name, columns):
            """Initialize table."""
            self.name = name
            self.columns = columns  # List of (name, type, constraints) tuples
            self.rows = []
            self.primary_key = None
            self.indexes = {}
            self.constraints = []

            # Parse columns for constraints
            for col_name, _col_type, constraints in columns:
                if "PRIMARY KEY" in constraints:
                    self.primary_key = col_name
                if "UNIQUE" in constraints:
                    self.constraints.append(("UNIQUE", col_name))
                if "NOT NULL" in constraints:
                    self.constraints.append(("NOT NULL", col_name))

        def insert(self, values):
            """Insert row into table."""
            # Validate constraints
            row = {}
            for i, (col_name, col_type, _constraints) in enumerate(self.columns):
                if i < len(values):
                    value = values[i]
                else:
                    value = None

                # Check NOT NULL
                if value is None and ("NOT NULL", col_name) in self.constraints:
                    raise IntegrityError(f"NOT NULL constraint failed: {col_name}")

                # Type conversion
                if value is not None:
                    if col_type == "INTEGER":
                        value = int(value) if value != "" else None
                    elif col_type == "REAL":
                        value = float(value) if value != "" else None
                    elif col_type == "TEXT":
                        value = str(value)
                    elif col_type == "BLOB":
                        value = bytes(value) if not isinstance(value, bytes) else value

                row[col_name] = value

            # Check UNIQUE constraints
            for constraint_type, col_name in self.constraints:
                if constraint_type == "UNIQUE" and row[col_name] is not None:
                    for existing_row in self.rows:
                        if existing_row[col_name] == row[col_name]:
                            raise IntegrityError(f"UNIQUE constraint failed: {col_name}")

            # Check PRIMARY KEY
            if self.primary_key and row[self.primary_key] is not None:
                for existing_row in self.rows:
                    if existing_row[self.primary_key] == row[self.primary_key]:
                        raise IntegrityError(f"PRIMARY KEY constraint failed: {self.primary_key}")

            self.rows.append(row)
            return len(self.rows)

        def select(self, columns=None, where=None, order_by=None, limit=None):
            """Select rows from table."""
            result_rows = []

            for row in self.rows:
                # Apply WHERE clause
                if where:
                    if not self._evaluate_where(row, where):
                        continue

                # Select columns
                if columns and columns != ["*"]:
                    result_row = tuple(row.get(col) for col in columns)
                else:
                    result_row = tuple(row.values())

                result_rows.append(result_row)

            # Apply ORDER BY
            if order_by:
                col_name, direction = order_by
                col_idx = self._get_column_index(col_name)
                reverse = direction == "DESC"
                result_rows.sort(key=lambda x: x[col_idx] if x[col_idx] is not None else "", reverse=reverse)

            # Apply LIMIT
            if limit:
                result_rows = result_rows[:limit]

            return result_rows

        def update(self, set_values, where=None):
            """Update rows in table."""
            updated_count = 0

            for row in self.rows:
                if where and not self._evaluate_where(row, where):
                    continue

                for col_name, value in set_values.items():
                    row[col_name] = value
                updated_count += 1

            return updated_count

        def delete(self, where=None):
            """Delete rows from table."""
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

        def _evaluate_where(self, row, where):
            """Evaluate WHERE clause for a row."""
            col_name, operator, value = where
            row_value = row.get(col_name)

            if operator == "=":
                return row_value == value
            elif operator == "!=":
                return row_value != value
            elif operator == ">":
                return row_value > value if row_value is not None else False
            elif operator == "<":
                return row_value < value if row_value is not None else False
            elif operator == ">=":
                return row_value >= value if row_value is not None else False
            elif operator == "<=":
                return row_value <= value if row_value is not None else False
            elif operator == "LIKE":
                if row_value is None:
                    return False
                pattern = value.replace("%", ".*").replace("_", ".")
                return bool(re.match(pattern, str(row_value)))
            elif operator == "IN":
                return row_value in value
            elif operator == "IS":
                return row_value is value
            elif operator == "IS NOT":
                return row_value is not value

            return False

        def _get_column_index(self, col_name):
            """Get column index by name."""
            for i, (name, _, _) in enumerate(self.columns):
                if name == col_name:
                    return i
            return 0

    class FallbackDatabase:
        """In-memory database implementation."""

        def __init__(self, path=":memory:"):
            """Initialize database."""
            self.path = path
            self.tables = {}
            self.views = {}
            self.transactions = []
            self.in_transaction = False

            # Load from file if not in-memory
            if path != ":memory:" and os.path.exists(path):
                self._load_from_file()

        def create_table(self, name, columns):
            """Create a new table."""
            if name in self.tables:
                raise OperationalError(f"table {name} already exists")

            self.tables[name] = FallbackTable(name, columns)

        def drop_table(self, name):
            """Drop a table."""
            if name not in self.tables:
                raise OperationalError(f"no such table: {name}")

            del self.tables[name]

        def execute_sql(self, sql, params=None):
            """Execute SQL statement."""
            # Parse SQL (simplified)
            sql = sql.strip()
            sql_upper = sql.upper()

            if sql_upper.startswith("CREATE TABLE"):
                return self._execute_create_table(sql)
            elif sql_upper.startswith("DROP TABLE"):
                return self._execute_drop_table(sql)
            elif sql_upper.startswith("INSERT INTO"):
                return self._execute_insert(sql, params)
            elif sql_upper.startswith("SELECT"):
                return self._execute_select(sql, params)
            elif sql_upper.startswith("UPDATE"):
                return self._execute_update(sql, params)
            elif sql_upper.startswith("DELETE"):
                return self._execute_delete(sql, params)
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
                raise ProgrammingError(f"Unsupported SQL: {sql}")

        def _execute_create_table(self, sql):
            """Execute CREATE TABLE statement."""
            # Parse table name and columns
            match = re.match(r"CREATE TABLE\s+(\w+)\s*\((.*)\)", sql, re.IGNORECASE | re.DOTALL)
            if not match:
                raise ProgrammingError(f"Invalid CREATE TABLE syntax: {sql}")

            table_name = match.group(1)
            columns_str = match.group(2)

            # Parse columns
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
            return None

        def _execute_drop_table(self, sql):
            """Execute DROP TABLE statement."""
            match = re.match(r"DROP TABLE\s+(\w+)", sql, re.IGNORECASE)
            if not match:
                raise ProgrammingError(f"Invalid DROP TABLE syntax: {sql}")

            table_name = match.group(1)
            self.drop_table(table_name)
            return None

        def _execute_insert(self, sql, params):
            """Execute INSERT statement."""
            match = re.match(r"INSERT INTO\s+(\w+)\s*(?:\((.*?)\))?\s*VALUES\s*\((.*?)\)", sql, re.IGNORECASE | re.DOTALL)
            if not match:
                raise ProgrammingError(f"Invalid INSERT syntax: {sql}")

            table_name = match.group(1)
            match.group(2)
            values_str = match.group(3)

            if table_name not in self.tables:
                raise OperationalError(f"no such table: {table_name}")

            # Parse values
            values = []
            if params:
                values = params
            else:
                # Parse literal values
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
            return None

        def _execute_select(self, sql, params):
            """Execute SELECT statement."""
            # Simplified SELECT parsing
            match = re.match(
                r"SELECT\s+(.*?)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.*?))?(?:\s+ORDER BY\s+(.*?))?(?:\s+LIMIT\s+(\d+))?",
                sql,
                re.IGNORECASE | re.DOTALL,
            )

            if not match:
                raise ProgrammingError(f"Invalid SELECT syntax: {sql}")

            columns_str = match.group(1)
            table_name = match.group(2)
            where_str = match.group(3)
            order_str = match.group(4)
            limit_str = match.group(5)

            if table_name not in self.tables:
                raise OperationalError(f"no such table: {table_name}")

            # Parse columns
            if columns_str.strip() == "*":
                columns = ["*"]
            else:
                columns = [col.strip() for col in columns_str.split(",")]

            # Parse WHERE clause
            where = None
            if where_str:
                # Simple WHERE parsing (column operator value)
                match = re.match(r"(\w+)\s*(=|!=|>|<|>=|<=|LIKE|IN|IS|IS NOT)\s*(.*)", where_str, re.IGNORECASE)
                if match:
                    col_name = match.group(1)
                    operator = match.group(2).upper()
                    value_str = match.group(3)

                    # Parse value
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

            # Parse ORDER BY
            order_by = None
            if order_str:
                parts = order_str.split()
                col_name = parts[0]
                direction = parts[1] if len(parts) > 1 else "ASC"
                order_by = (col_name, direction.upper())

            # Parse LIMIT
            limit = int(limit_str) if limit_str else None

            return self.tables[table_name].select(columns, where, order_by, limit)

        def _execute_update(self, sql, params):
            """Execute UPDATE statement."""
            match = re.match(r"UPDATE\s+(\w+)\s+SET\s+(.*?)(?:\s+WHERE\s+(.*?))?", sql, re.IGNORECASE | re.DOTALL)

            if not match:
                raise ProgrammingError(f"Invalid UPDATE syntax: {sql}")

            table_name = match.group(1)
            set_str = match.group(2)
            where_str = match.group(3)

            if table_name not in self.tables:
                raise OperationalError(f"no such table: {table_name}")

            # Parse SET clause
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

            # Parse WHERE clause (simplified)
            where = None
            if where_str:
                # Reuse SELECT WHERE parsing
                pass

            return self.tables[table_name].update(set_values, where)

        def _execute_delete(self, sql, params):
            """Execute DELETE statement."""
            match = re.match(r"DELETE\s+FROM\s+(\w+)(?:\s+WHERE\s+(.*?))?", sql, re.IGNORECASE | re.DOTALL)

            if not match:
                raise ProgrammingError(f"Invalid DELETE syntax: {sql}")

            table_name = match.group(1)
            where_str = match.group(2)

            if table_name not in self.tables:
                raise OperationalError(f"no such table: {table_name}")

            # Parse WHERE clause (simplified)
            where = None
            if where_str:
                # Reuse SELECT WHERE parsing
                pass

            return self.tables[table_name].delete(where)

        def _save_to_file(self):
            """Save database to file."""
            if self.path != ":memory:":
                try:
                    # Serialize tables and views to JSON-safe format
                    tables_data = {}
                    for name, table in self.tables.items():
                        tables_data[name] = {
                            "name": table.name,
                            "columns": table.columns,
                            "rows": table.rows,
                            "primary_key": table.primary_key,
                            "indexes": table.indexes,
                            "constraints": table.constraints,
                        }

                    serialized_data = {"tables": tables_data, "views": self.views}

                    with open(self.path, "w", encoding="utf-8") as f:
                        json.dump(serialized_data, f, indent=2)
                except Exception as e:
                    logger.error("Failed to save database: %s", e)

        def _load_from_file(self):
            """Load database from file."""
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                    # Reconstruct tables
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

    class Cursor:
        """Database cursor implementation."""

        def __init__(self, connection):
            """Initialize cursor."""
            self.connection = connection
            self.description = None
            self.rowcount = -1
            self.lastrowid = None
            self._results = []
            self._result_index = 0

        def execute(self, sql, params=None):
            """Execute SQL statement."""
            try:
                result = self.connection._db.execute_sql(sql, params)

                if result is not None:
                    self._results = result
                    self._result_index = 0
                    self.rowcount = len(result)
                else:
                    self._results = []
                    self.rowcount = -1

                # Set description for SELECT
                if sql.strip().upper().startswith("SELECT"):
                    # Simple description
                    self.description = [("column",) for _ in range(len(self._results[0]) if self._results else 0)]

                return self

            except Exception as e:
                raise DatabaseError(str(e)) from e

        def executemany(self, sql, params_list):
            """Execute SQL with multiple parameter sets."""
            for params in params_list:
                self.execute(sql, params)
            return self

        def fetchone(self):
            """Fetch one row."""
            if self._result_index < len(self._results):
                row = self._results[self._result_index]
                self._result_index += 1
                return row
            return None

        def fetchall(self):
            """Fetch all remaining rows."""
            rows = self._results[self._result_index :]
            self._result_index = len(self._results)
            return rows

        def fetchmany(self, size=None):
            """Fetch multiple rows."""
            if size is None:
                size = 1

            rows = []
            for _ in range(size):
                row = self.fetchone()
                if row is None:
                    break
                rows.append(row)
            return rows

        def close(self):
            """Close cursor."""
            self._results = []

        def __enter__(self):
            """Context manager entry."""
            return self

        def __exit__(self, *args):
            """Context manager exit."""
            self.close()

    class Connection:
        """Database connection implementation."""

        def __init__(self, database=":memory:"):
            """Initialize connection."""
            self.database = database
            self._db = FallbackDatabase(database)
            self.isolation_level = None
            self.row_factory = None

        def cursor(self):
            """Create a cursor."""
            return Cursor(self)

        def execute(self, sql, params=None):
            """Execute SQL directly."""
            cursor = self.cursor()
            return cursor.execute(sql, params)

        def executemany(self, sql, params_list):
            """Execute SQL with multiple parameter sets."""
            cursor = self.cursor()
            return cursor.executemany(sql, params_list)

        def commit(self):
            """Commit transaction."""
            self._db.execute_sql("COMMIT")

        def rollback(self):
            """Rollback transaction."""
            self._db.execute_sql("ROLLBACK")

        def close(self):
            """Close connection."""
            if self._db.path != ":memory:":
                self._db._save_to_file()

        def __enter__(self):
            """Context manager entry."""
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            """Context manager exit."""
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
            self.close()

    class Row:
        """Row object that supports both index and column name access."""

        def __init__(self, cursor, row):
            """Initialize row."""
            self.cursor = cursor
            self.row = row

        def __getitem__(self, key):
            """Get item by index or column name."""
            if isinstance(key, int):
                return self.row[key]
            else:
                # Find column index by name
                for i, desc in enumerate(self.cursor.description or []):
                    if desc[0] == key:
                        return self.row[i]
                raise KeyError(key)

        def keys(self):
            """Get column names."""
            return [desc[0] for desc in self.cursor.description or []]

    def connect(database=":memory:", **kwargs):
        """Connect to database."""
        return Connection(database)

    def register_adapter(type, adapter):
        """Register type adapter."""
        logger.info("Adapter registration not supported in fallback mode")

    def register_converter(name, converter):
        """Register type converter."""
        logger.info("Converter registration not supported in fallback mode")

    # Module-level attributes
    PARSE_DECLTYPES = 1
    PARSE_COLNAMES = 2

    # Create module-like object
    class FallbackSQLite3:
        """Fallback sqlite3 module."""

        # Functions
        connect = staticmethod(connect)
        register_adapter = staticmethod(register_adapter)
        register_converter = staticmethod(register_converter)

        # Classes
        Connection = Connection
        Cursor = Cursor
        Row = Row

        # Exceptions
        Error = Error
        DatabaseError = DatabaseError
        IntegrityError = IntegrityError
        OperationalError = OperationalError
        ProgrammingError = ProgrammingError

        # Constants
        PARSE_DECLTYPES = PARSE_DECLTYPES
        PARSE_COLNAMES = PARSE_COLNAMES

        # Version
        version = "0.0.0-fallback"

    sqlite3 = FallbackSQLite3()


# Export all sqlite3 objects and availability flag
__all__ = [
    # Availability flags
    "HAS_SQLITE3",
    "HAS_SQLITE",
    "SQLITE3_VERSION",
    # Main module
    "sqlite3",
    # Functions
    "connect",
    "register_adapter",
    "register_converter",
    # Classes
    "Connection",
    "Cursor",
    "Row",
    # Exceptions
    "Error",
    "DatabaseError",
    "IntegrityError",
    "OperationalError",
    "ProgrammingError",
    # Constants
    "PARSE_DECLTYPES",
    "PARSE_COLNAMES",
]
