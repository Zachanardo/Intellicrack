"""Intellicrack License Audit Database Manager.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from intellicrack.core.database.models import Base, LicenseEntry, LicenseLog


if TYPE_CHECKING:
    from sqlalchemy.engine import Engine


class LicenseAuditDB:
    """Database operations for license management and audit tracking.

    Provides SQLAlchemy-based database operations for storing, validating,
    and auditing software license information. Uses SQLite with connection
    pooling for thread-safe access.

    Attributes:
        db_path: Path to SQLite database file.
        engine: SQLAlchemy database engine.
        SessionLocal: Session factory for database connections.
    """

    def __init__(self, db_path: str | None = None) -> None:
        """Initialize license audit database with SQLite engine and session factory.

        Creates SQLAlchemy engine and session factory for license database operations,
        initializes database schema with license, activation, and logging tables.

        Args:
            db_path: Path to SQLite database file. Defaults to LICENSE_SERVER_DB
                from intellicrack.data if not specified.
        """
        self.logger: logging.Logger = logging.getLogger(f"{__name__}.LicenseAuditDB")
        if db_path is None:
            from intellicrack.data import LICENSE_SERVER_DB

            db_path = str(LICENSE_SERVER_DB)
        self.db_path: str = db_path
        self.engine: Engine = create_engine(
            f"sqlite:///{db_path}",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        self.SessionLocal: sessionmaker[Session] = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )
        self._create_tables()

    def _create_tables(self) -> None:
        """Create database tables for license, activation, and logging data.

        Uses SQLAlchemy ORM metadata to create LicenseEntry, LicenseActivation,
        and LicenseLog tables in the SQLite database if they do not already exist.
        """
        try:
            Base.metadata.create_all(bind=self.engine)
            self.logger.info("Database tables created successfully")
        except Exception:
            self.logger.exception("Database table creation failed")

    def get_db(self) -> Session:
        """Get database session for license operations.

        Creates and returns a new SQLAlchemy session for performing database
        operations. Caller is responsible for closing the session.

        Returns:
            SQLAlchemy Session instance for database operations.
        """
        return self.SessionLocal()

    def validate_license(
        self, license_key: str, product_name: str
    ) -> LicenseEntry | None:
        """Validate license in database and return license entry if found.

        Queries the database for a license matching both the provided key
        and product name to ensure license-product binding.

        Args:
            license_key: License key string to validate.
            product_name: Software product name associated with license.

        Returns:
            LicenseEntry object if found, None otherwise.
        """
        try:
            db = self.SessionLocal()
            license_entry = (
                db.query(LicenseEntry)
                .filter(
                    LicenseEntry.license_key == license_key,
                    LicenseEntry.product_name == product_name,
                )
                .first()
            )
            db.close()
            return license_entry
        except Exception:
            self.logger.exception("License validation error")
            return None

    def log_operation(
        self,
        license_key: str,
        operation: str,
        client_ip: str,
        *,
        success: bool,
        details: str = "",
    ) -> None:
        """Log license operation to database for audit purposes.

        Records license validation attempts, activations, deactivations,
        and other operations for compliance and security auditing.

        Args:
            license_key: License key string for operation logging.
            operation: Operation name or type being performed.
            client_ip: Client IP address making the request.
            success: Operation success status (keyword-only).
            details: Operation details or error message (keyword-only, optional).
        """
        try:
            db = self.SessionLocal()
            log_entry = LicenseLog(
                license_key=license_key,
                operation=operation,
                client_ip=client_ip,
                success=success,
                details=details,
            )
            db.add(log_entry)
            db.commit()
            db.close()
        except Exception:
            self.logger.exception("Operation logging failed")
