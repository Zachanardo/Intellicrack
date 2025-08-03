"""
Logging Package for Intellicrack

Provides audit logging and monitoring capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
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
    'AuditLogger',
    'AuditEvent',
    'AuditEventType',
    'AuditSeverity',
    'get_audit_logger',
    'log_exploit_attempt',
    'log_binary_analysis',
    'log_vm_operation',
    'log_credential_access',
    'log_tool_execution'
]
