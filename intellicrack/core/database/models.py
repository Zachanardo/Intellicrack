"""Intellicrack Database ORM Models.

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

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """SQLAlchemy declarative base class for license database models."""


class LicenseEntry(Base):
    """License database entry model.

    Stores license key information including type, product association,
    validity status, expiration, and user limits for license tracking.

    Attributes:
        id: Primary key identifier.
        license_key: Unique license key string.
        license_type: Type of license (e.g., flexlm, hasp, kms).
        product_name: Name of the licensed product.
        version: Product version string.
        status: License status (valid, expired, revoked).
        created_date: Timestamp when license was created.
        expiry_date: Optional expiration timestamp.
        max_users: Maximum concurrent users allowed.
        current_users: Current active user count.
        hardware_fingerprint: Optional hardware binding identifier.
        custom_data: Optional JSON or text metadata.
        activations: Related activation records.
    """

    __tablename__ = "licenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    license_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    license_type: Mapped[str] = mapped_column(String(50), nullable=False)
    product_name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="valid")
    created_date: Mapped[datetime | None] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC)
    )
    expiry_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    max_users: Mapped[int] = mapped_column(Integer, default=1)
    current_users: Mapped[int] = mapped_column(Integer, default=0)
    hardware_fingerprint: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    custom_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    activations: Mapped[list[LicenseActivation]] = relationship(
        "LicenseActivation", back_populates="license"
    )


class LicenseActivation(Base):
    """License activation tracking model.

    Records individual license activations including client information,
    hardware binding, and activity timestamps for audit purposes.

    Attributes:
        id: Primary key identifier.
        license_id: Foreign key to parent license.
        client_ip: IP address of activating client.
        hardware_fingerprint: Hardware identifier for binding.
        activation_time: Timestamp of activation.
        last_checkin: Most recent heartbeat timestamp.
        is_active: Whether activation is currently active.
        user_agent: Client user agent string.
        license: Parent license relationship.
    """

    __tablename__ = "activations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    license_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("licenses.id"), nullable=False
    )
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    hardware_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    activation_time: Mapped[datetime | None] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC)
    )
    last_checkin: Mapped[datetime | None] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC)
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    license: Mapped[LicenseEntry] = relationship(
        "LicenseEntry", back_populates="activations"
    )


class LicenseLog(Base):
    """License operation logging model.

    Records all license operations for audit trail including validation
    attempts, activations, deactivations, and errors.

    Attributes:
        id: Primary key identifier.
        license_key: License key involved in operation.
        operation: Type of operation performed.
        client_ip: IP address of requesting client.
        timestamp: Operation timestamp.
        success: Whether operation succeeded.
        details: Additional operation details or error messages.
    """

    __tablename__ = "license_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    license_key: Mapped[str] = mapped_column(String(255), nullable=False)
    operation: Mapped[str] = mapped_column(String(100), nullable=False)
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    timestamp: Mapped[datetime | None] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC)
    )
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
