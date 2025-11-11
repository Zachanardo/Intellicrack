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

import logging

logger = logging.getLogger(__name__)

# Lazy-load audit logger to prevent circular imports
_audit_logger_loaded = False
_audit_exports = {}


def _load_audit_logger() -> None:
    """Lazy load audit logger exports to prevent circular imports."""
    global _audit_logger_loaded, _audit_exports
    if not _audit_logger_loaded:
        try:
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
            _audit_exports = {
                'AuditEvent': AuditEvent,
                'AuditEventType': AuditEventType,
                'AuditLogger': AuditLogger,
                'AuditSeverity': AuditSeverity,
                'get_audit_logger': get_audit_logger,
                'log_binary_analysis': log_binary_analysis,
                'log_credential_access': log_credential_access,
                'log_exploit_attempt': log_exploit_attempt,
                'log_tool_execution': log_tool_execution,
                'log_vm_operation': log_vm_operation,
            }
        except ImportError as e:
            logger.warning("Failed to import audit_logger: %s", e)
        _audit_logger_loaded = True


def __getattr__(name):
    """Lazy load audit logger attributes."""
    _load_audit_logger()
    if name in _audit_exports:
        return _audit_exports[name]
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


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
