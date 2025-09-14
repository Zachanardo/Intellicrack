"""Logging Package for Intellicrack.

Provides audit logging and monitoring capabilities.

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

from .audit_logger import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    AuditSeverity,
    get_audit_logger,
    log_binary_analysis,
    log_credential_access,
    log_exploit_attempt,
    log_tool_execution,
    log_vm_operation,
)

__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditLogger",
    "AuditSeverity",
    "get_audit_logger",
    "log_binary_analysis",
    "log_credential_access",
    "log_exploit_attempt",
    "log_tool_execution",
    "log_vm_operation",
]
