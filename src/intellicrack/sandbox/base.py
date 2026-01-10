"""Base sandbox protocol and types.

This module defines the base class for sandbox implementations
that provide isolated execution environments for binary analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal, TypedDict

from ..core.logging import get_logger

_logger = get_logger("sandbox.base")

SandboxStatus = Literal["stopped", "starting", "running", "stopping", "error"]
ExecutionResult = Literal["success", "timeout", "error", "crashed"]


class FileChange(TypedDict):
    """Represents a file system change in the sandbox."""

    path: str
    operation: Literal["created", "modified", "deleted", "renamed"]
    old_path: str | None
    timestamp: str
    size: int | None


class RegistryChange(TypedDict):
    """Represents a registry change in the sandbox."""

    key: str
    value_name: str | None
    operation: Literal["created", "modified", "deleted"]
    value_type: str | None
    value_data: str | None
    timestamp: str


class NetworkActivity(TypedDict):
    """Represents network activity in the sandbox."""

    protocol: Literal["tcp", "udp", "icmp", "other"]
    direction: Literal["inbound", "outbound"]
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    timestamp: str
    bytes_sent: int
    bytes_received: int


class ProcessActivity(TypedDict):
    """Represents process activity in the sandbox."""

    pid: int
    name: str
    path: str | None
    command_line: str | None
    parent_pid: int | None
    operation: Literal["created", "terminated"]
    exit_code: int | None
    timestamp: str


@dataclass
class SandboxConfig:
    """Configuration for sandbox execution.

    Attributes:
        timeout_seconds: Maximum execution time.
        memory_limit_mb: Memory limit in megabytes.
        network_enabled: Whether network access is allowed.
        clipboard_enabled: Whether clipboard sharing is allowed.
        audio_enabled: Whether audio is enabled.
        video_enabled: Whether video/GPU is enabled.
        printer_enabled: Whether printing is allowed.
        shared_folders: Folders shared with the sandbox.
        startup_commands: Commands to run at startup.
        environment_variables: Environment variables to set.
    """

    timeout_seconds: int = 300
    memory_limit_mb: int = 2048
    network_enabled: bool = False
    clipboard_enabled: bool = False
    audio_enabled: bool = False
    video_enabled: bool = False
    printer_enabled: bool = False
    shared_folders: list[tuple[Path, str, bool]] = field(default_factory=list)
    startup_commands: list[str] = field(default_factory=list)
    environment_variables: dict[str, str] = field(default_factory=dict)


@dataclass
class SandboxState:
    """Current state of the sandbox.

    Attributes:
        status: Current sandbox status.
        started_at: When the sandbox was started.
        pid: Process ID of the sandbox.
        last_error: Last error message if any.
    """

    status: SandboxStatus = "stopped"
    started_at: datetime | None = None
    pid: int | None = None
    last_error: str | None = None


@dataclass
class ExecutionReport:
    """Report of a binary execution in the sandbox.

    Attributes:
        result: Execution result status.
        exit_code: Process exit code.
        stdout: Standard output.
        stderr: Standard error.
        duration_seconds: Execution duration.
        file_changes: File system changes detected.
        registry_changes: Registry changes detected.
        network_activity: Network activity detected.
        process_activity: Process activity detected.
    """

    result: ExecutionResult
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    file_changes: list[FileChange] = field(default_factory=list)
    registry_changes: list[RegistryChange] = field(default_factory=list)
    network_activity: list[NetworkActivity] = field(default_factory=list)
    process_activity: list[ProcessActivity] = field(default_factory=list)


class SandboxError(Exception):
    """Exception raised for sandbox-related errors."""

    def __init__(self, message: str, details: str | None = None) -> None:
        """Initialize the sandbox error.

        Args:
            message: Error message.
            details: Optional detailed information.
        """
        super().__init__(message)
        self.details = details


class SandboxBase:
    """Base class for sandbox implementations.

    Provides common functionality for all sandbox types.
    Subclasses should override methods to provide actual sandbox functionality.

    Attributes:
        _config: Sandbox configuration.
        _state: Current sandbox state.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialize the sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        self._config = config or SandboxConfig()
        self._state = SandboxState()

    @property
    def state(self) -> SandboxState:
        """Get current sandbox state.

        Returns:
            Current SandboxState.
        """
        return self._state

    @property
    def config(self) -> SandboxConfig:
        """Get sandbox configuration.

        Returns:
            Current SandboxConfig.
        """
        return self._config

    async def is_available(self) -> bool:
        """Check if this sandbox type is available.

        Returns:
            True if sandbox can be used.
        """
        _logger.debug("Base sandbox is_available called - returning False")
        return False

    async def start(self) -> None:
        """Start the sandbox environment.

        Raises:
            SandboxError: If sandbox cannot be started.
        """
        raise SandboxError(
            "Sandbox not implemented",
            "Use a concrete sandbox implementation like WindowsSandbox",
        )

    async def stop(self) -> None:
        """Stop the sandbox environment.

        Raises:
            SandboxError: If sandbox cannot be stopped.
        """
        if self._state.status == "stopped":
            _logger.debug("Sandbox already stopped")
            return

        raise SandboxError(
            "Sandbox not implemented",
            "Use a concrete sandbox implementation like WindowsSandbox",
        )

    async def restart(self) -> None:
        """Restart the sandbox environment.

        Raises:
            SandboxError: If sandbox cannot be restarted.
        """
        await self.stop()
        await self.start()

    async def execute(
        self,
        command: str,
        timeout: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute a command in the sandbox.

        Args:
            command: Command to execute.
            timeout: Optional timeout override.
            working_directory: Optional working directory.

        Returns:
            Tuple of (exit_code, stdout, stderr).

        Raises:
            SandboxError: If execution fails.
        """
        raise SandboxError(
            "Sandbox execution not implemented",
            "Use a concrete sandbox implementation like WindowsSandbox",
        )

    async def run_binary(
        self,
        binary_path: Path,
        args: list[str] | None = None,
        timeout: int | None = None,
        monitor: bool = True,
    ) -> ExecutionReport:
        """Run a binary in the sandbox with monitoring.

        Args:
            binary_path: Path to the binary to run.
            args: Optional command line arguments.
            timeout: Optional timeout override.
            monitor: Whether to monitor behavior.

        Returns:
            ExecutionReport with results and activity.

        Raises:
            SandboxError: If execution fails.
        """
        raise SandboxError(
            "Binary execution not implemented",
            "Use a concrete sandbox implementation like WindowsSandbox",
        )

    async def copy_to_sandbox(self, source: Path, dest: str) -> None:
        """Copy a file into the sandbox.

        Args:
            source: Local source path.
            dest: Destination path in sandbox.

        Raises:
            SandboxError: If copy fails.
        """
        raise SandboxError(
            "File copy not implemented",
            "Use a concrete sandbox implementation like WindowsSandbox",
        )

    async def copy_from_sandbox(self, source: str, dest: Path) -> None:
        """Copy a file from the sandbox.

        Args:
            source: Source path in sandbox.
            dest: Local destination path.

        Raises:
            SandboxError: If copy fails.
        """
        raise SandboxError(
            "File copy not implemented",
            "Use a concrete sandbox implementation like WindowsSandbox",
        )

    async def take_snapshot(self, name: str) -> str:
        """Take a snapshot of the sandbox state.

        Args:
            name: Snapshot name.

        Returns:
            Snapshot identifier.

        Raises:
            SandboxError: If not supported.
        """
        raise SandboxError("Snapshots not supported by this sandbox type")

    async def restore_snapshot(self, snapshot_id: str) -> None:
        """Restore a sandbox snapshot.

        Args:
            snapshot_id: Snapshot identifier.

        Raises:
            SandboxError: If not supported.
        """
        raise SandboxError("Snapshots not supported by this sandbox type")
