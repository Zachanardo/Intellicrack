"""Sandbox implementations for isolated binary execution.

This package provides sandbox environments for safe execution and
behavioral analysis of potentially malicious binaries.
"""

from __future__ import annotations

from .base import (
    ExecutionReport,
    ExecutionResult,
    FileChange,
    NetworkActivity,
    ProcessActivity,
    RegistryChange,
    SandboxBase,
    SandboxConfig,
    SandboxError,
    SandboxState,
    SandboxStatus,
)
from .manager import SandboxInstance, SandboxManager, SandboxType
from .windows import WindowsSandbox

__all__: list[str] = [
    # Base types
    "SandboxBase",
    "SandboxConfig",
    "SandboxState",
    "SandboxError",
    "ExecutionReport",
    # Type aliases
    "SandboxStatus",
    "ExecutionResult",
    # TypedDicts
    "FileChange",
    "RegistryChange",
    "NetworkActivity",
    "ProcessActivity",
    # Implementations
    "WindowsSandbox",
    # Manager
    "SandboxManager",
    "SandboxInstance",
    "SandboxType",
]
